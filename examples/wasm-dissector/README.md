# A tcpcat dissector in ~30 lines

This directory is a ready-to-build WebAssembly dissector: it recognises Redis
on any port and reads its version.

```bash
./build.sh                                   # -> redis.wasm (TinyGo, or Docker if TinyGo isn't installed)
tcpcat -sT -p 6379 --scripts . <target>
#   |_ redis: auth=none service=redis version=7.2.4
```

To write your own, copy this directory and edit **`dissector.go`** only: one
`Dissect(ip, port)` function that calls `Probe(...)` to talk to the port being
scanned and returns what it recognised. `./build.sh myname` produces
`myname.wasm`.

| File | Role |
|---|---|
| `dissector.go` | your dissector (the Redis example) |
| `sdk.go` | glue with tcpcat's ABI: `Probe`, memory exports, JSON output |
| `build.sh` | compiles to WebAssembly (`wasm-unknown` target) |
| `go.mod` | keeps this TinyGo program out of tcpcat's own Go build |

The sandbox rules, the ABI and a Rust outline are in
[docs/WASM_SDK.md](../../docs/WASM_SDK.md).
