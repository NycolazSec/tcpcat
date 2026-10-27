# tcpcat scripts hub (reference)

This directory is a **reference hub**: the exact layout tcpcat's
`tcpcat scripts` command expects. Copy it into its own public repo (the default
the CLI looks for is `NycolazSec/tcpcat-scripts`) to run a community hub, or
point `--index` / `$TCPCAT_SCRIPTS_INDEX` at any copy of it.

```
index.json            # the catalog
dissectors/
  redis.wasm          # a module, referenced by index.json with its sha256
```

## How it works

A hub is just a static `index.json` served over HTTPS. Each entry pins the
module's **SHA-256**, so `tcpcat scripts install` verifies integrity before the
module ever reaches the scanner — a tampered or corrupted `.wasm` is rejected.
`url` may be absolute or **relative to index.json** (as above), which keeps the
hub self-contained whether it's served from GitHub raw or a local path.

```jsonc
{
  "schema_version": 1,
  "dissectors": [
    {
      "name": "redis",                 // also the installed filename: redis.wasm
      "description": "…",
      "version": "1.0.0",
      "author": "…",
      "license": "AGPL-3.0-only",
      "homepage": "https://…",
      "ports": [6379],                 // informational
      "url": "dissectors/redis.wasm",  // absolute, or relative to index.json
      "sha256": "fb1d58a1…41c7"         // required; install is pinned to it
    }
  ]
}
```

## Try it locally

```bash
export TCPCAT_SCRIPTS_INDEX="$(pwd)/examples/scripts-hub/index.json"
tcpcat scripts search
tcpcat scripts install redis
tcpcat scripts list
tcpcat -sV -p 6379 --scripts "$(tcpcat scripts dir)" 127.0.0.1
```

## Submitting a dissector

1. Write and build it from the template in
   [`examples/wasm-dissector`](../wasm-dissector) (`./build.sh myname`).
2. Add `dissectors/myname.wasm` and an entry in `index.json` with its
   `sha256` (`sha256sum dissectors/myname.wasm`).
3. Open a PR. The validation workflow
   ([`validate.yml`](validate.yml)) checks that every entry's `sha256` matches
   its file, names are unique and safe, and the JSON is well-formed — so a bad
   or mismatched module can't land in the catalog.

Modules run in tcpcat's sandbox (wazero, no WASI): a dissector can only talk to
the port being scanned, through one host function, within a strict probe
budget. See [docs/WASM_SDK.md](../../docs/WASM_SDK.md).
