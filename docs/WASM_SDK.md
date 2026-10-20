# Writing a tcpcat dissector in WebAssembly

A dissector is a small WebAssembly module that tcpcat runs against every open
port it finds. It can talk to that port, read what comes back, and report what
it recognised: a product, a version, a misconfiguration. Where Nmap has Lua
scripts (NSE), tcpcat has sandboxed WebAssembly, so a dissector can be written
in any language that compiles to it.

## Quick start (TinyGo)

```bash
cd examples/wasm-dissector
./build.sh                                  # -> redis.wasm (needs TinyGo, or Docker)
tcpcat -sT -p 6379 --scripts . 192.0.2.10
#   [+] 192.0.2.10:6379 ─ OPEN
#       |_ redis: auth=none service=redis version=7.2.4
```

`dissector.go` is the only file to edit. It is one function:

```go
func Dissect(ip string, port int) map[string]string {
	reply := string(Probe([]byte("PING\r\n")))
	if strings.HasPrefix(reply, "+PONG") {
		return map[string]string{"service": "redis"}
	}
	return nil // not ours
}
```

- `Probe(request)` sends bytes to the port being scanned and returns the answer.
  `Probe(nil)` just reads the banner.
- Return key/value facts, or `nil` when the port isn't the service you look for.
- `sdk.go` next to it is the glue with the ABI below; you shouldn't need to touch it.

Every `*.wasm` file in the `--scripts` directory is loaded; a module's file
name is its name in the output. Results are printed under the port and stored
in the JSON report (`-j`) as `"scripts": {"redis": {"service": "redis", ...}}`.

## What a dissector can and cannot do

The module runs in a sandbox (wazero, no WASI): no files, no clock, no
environment, no sockets. Its one capability is the host function
`tcpcat.probe`, which:

- connects **only to the host and port being scanned** — a dissector cannot
  pick another address, so it can't be used to reach anything the operator
  didn't target;
- is limited to **4 probes per run** and **64 KiB per answer**, so a dissector
  can't hammer a fragile service or move bulk data;
- is bounded by the scan's timing template (`-T`): a run that takes too long is
  cancelled.

Keep probes read-only (a `PING`, a version query, a banner read). Dissectors
run under the same authorized-use rules as the scanner itself, see
[NOTICE.md](../NOTICE.md).

## The ABI, for other languages

A module must export three functions and may import one.

| Direction | Signature | Meaning |
|---|---|---|
| export | `allocate(size: i32) -> i32` | return a pointer to `size` writable bytes in the module's memory |
| export | `deallocate(ptr: i32, size: i32)` | the host is done with a buffer it was given |
| export | `run(port: i32, ip_ptr: i32, ip_len: i32) -> i64` | examine the target; return `(ptr << 32) \| len` of a UTF-8 JSON object of string values, or `0` for "nothing to report" |
| import | `tcpcat.probe(req_ptr: i32, req_len: i32, resp_ptr: i32, resp_cap: i32) -> i32` | send `req`, write up to `resp_cap` answer bytes at `resp_ptr`; returns the byte count, or `-1` connect failed, `-2` probe budget exceeded, `-3` buffer out of bounds |

Call sequence for each open port: the host calls `allocate(len(ip))`, writes
the target IP there, calls `run`, reads the JSON at the returned pointer, then
calls `deallocate` for both buffers. A fresh instance is created per run, so
globals don't carry over between ports. Modules that initialise in
`_initialize` (TinyGo, Rust `cdylib`) or `_start` are both supported.

A Rust dissector is the same three exports plus:

```rust
#[link(wasm_import_module = "tcpcat")]
extern "C" { fn probe(req: *const u8, req_len: u32, resp: *mut u8, resp_cap: u32) -> i32; }
```

built with `cargo build --release --target wasm32-unknown-unknown`.

## Testing a dissector

Point it at a service you run yourself (`docker run -p 127.0.0.1:6379:6379
redis`, then `tcpcat -sT -Pn -p 6379 --scripts . 127.0.0.1`). The engine's own
tests (`internal/scripting/engine_test.go`) load compiled fixtures against
loopback servers and are a template for testing yours; `testdata/build.sh`
rebuilds those fixtures.

## Contributing one

Open a pull request adding your dissector's source under `examples/` (or
propose a `dissectors/` collection in a Discussion). Say which product and
versions you tested it against, and keep its probes read-only.
