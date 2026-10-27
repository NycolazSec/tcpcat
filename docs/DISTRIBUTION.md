# Distribution channels

How tcpcat reaches users, and what has to be set up for each channel. The goal
is simple: the more package managers carry tcpcat, the more people discover it
without ever visiting the repo.

| Channel | Command | Status | Setup needed |
|---|---|---|---|
| Go | `go install github.com/NycolazSec/tcpcat/cmd/tcpcat@latest` | ✅ live | none |
| Prebuilt binaries | download from Releases | ✅ live | none (GoReleaser) |
| Debian/RPM | `.deb` / `.rpm` on Releases | ✅ live | none (GoReleaser `nfpms`) |
| macOS installer | `.dmg` / `.pkg` on Releases | ✅ live | none (release workflow) |
| Container (GHCR) | `docker run ghcr.io/nycolazsec/tcpcat:latest ...` | ✅ live | make package public once |
| BlackArch | `pacman -S tcpcat` | 🟡 PKGBUILD in repo | submit/refresh upstream |
| Homebrew | `brew install nycolazsec/tap/tcpcat` | ⚪ ready, off | tap repo + PAT secret |
| AUR | `yay -S tcpcat-bin` | ⚪ ready, off | AUR package + SSH key |

## Container image (GHCR) — live

The release workflow builds and pushes multi-arch images (`linux/amd64`,
`linux/arm64`) to `ghcr.io/nycolazsec/tcpcat` on every `v*` tag, using the
built-in `GITHUB_TOKEN`. One manual step the first time:

1. After the first tagged release, open the repo → **Packages** → `tcpcat` →
   **Package settings** → set visibility to **Public**, so `docker pull` works
   without authentication.

Run it (raw sockets need extra capabilities):

```bash
docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
  ghcr.io/nycolazsec/tcpcat:latest -sV -p 22,80,443 scanme.nmap.org
```

The eBPF/AF_XDP engine (`--ebpf`) needs `--privileged --network=host`.

## Homebrew tap — ready, currently off

The `brews:` block in [.goreleaser.yaml](../.goreleaser.yaml) is written but
commented out, because publishing to a tap needs a token that can push to a
*second* repo (the built-in `GITHUB_TOKEN` cannot).

1. Create a **public** repo `NycolazSec/homebrew-tap`.
2. Create a fine-grained Personal Access Token scoped to that repo with
   **Contents: read and write**.
3. In this repo: **Settings → Secrets and variables → Actions → New secret**,
   name `HOMEBREW_TAP_GITHUB_TOKEN`, value = the PAT.
4. Uncomment the `brews:` block in `.goreleaser.yaml` **and** the
   `HOMEBREW_TAP_GITHUB_TOKEN` line in `.github/workflows/release.yml`.
5. Tag a release. Users then run `brew install nycolazsec/tap/tcpcat`.

## AUR (`tcpcat-bin`) — ready, currently off

The `aurs:` block in `.goreleaser.yaml` is written but commented out.

1. Create an account on https://aur.archlinux.org and add an SSH public key.
2. Register the package name `tcpcat-bin` (first push creates it).
3. Add your AUR SSH **private** key as the repo secret `AUR_KEY`.
4. Uncomment the `aurs:` block in `.goreleaser.yaml` and the `AUR_KEY` line in
   the release workflow.
5. Tag a release.

## BlackArch

[`packaging/blackarch/PKGBUILD`](../packaging/blackarch/PKGBUILD) tracks git and
is pinned at `v1.3.0` — refresh `pkgver` and submit/update it upstream via the
[blackarch/blackarch](https://github.com/BlackArch/blackarch) packages tree so
`pacman -S tcpcat` stays current. Being in BlackArch (and, ideally, Kali)
reaches the pentest audience directly through their distro.

## Testing the config without publishing

GoReleaser can run the whole pipeline locally without pushing anything:

```bash
goreleaser release --snapshot --clean --skip=publish,sign
```

This builds the binaries, packages, and the Docker image so you can catch
config errors before tagging a real release.
