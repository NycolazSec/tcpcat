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
| BlackArch | `pacman -S tcpcat` | ✅ live | none (git package, rebuilt by BlackArch) |
| Homebrew (tap) | `brew install nycolazsec/tap/tcpcat` | ✅ live | renew the PAT yearly |
| Homebrew (core) | `brew install tcpcat` | ⚪ not eligible yet | notability, see below |
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

## Homebrew tap — live

Users install with:

```bash
brew install nycolazsec/tap/tcpcat
```

Naming the tap in full is what lets Homebrew 7+ load a third-party formula: it
records the formula as trusted. After that, `brew upgrade tcpcat` and the short
name work. A bare `brew install tcpcat` only works once tcpcat is in
homebrew-core (below).

GoReleaser's `brews:` block in [.goreleaser.yaml](../.goreleaser.yaml) writes
`Formula/tcpcat.rb` to [NycolazSec/homebrew-tap](https://github.com/NycolazSec/homebrew-tap)
on every release. The formula for v1.7.0 was published by hand on 2026-11-18;
the next release overwrites it.

Publishing needs a token that can push to a *second* repo (the built-in
`GITHUB_TOKEN` cannot): the secret `HOMEBREW_TAP_GITHUB_TOKEN` holds a
fine-grained PAT with **Contents: read and write** on `homebrew-tap` only.
**It expires.** When it does, the release workflow fails at the Homebrew step:
create a new PAT with the same scope and replace the secret.

## Homebrew core (`brew install tcpcat`) — not eligible yet

homebrew-core is the official repository: a formula there installs with
`brew install tcpcat`, with no tap. Its
[acceptance policy](https://docs.brew.sh/Package-Acceptance-Policy) requires a
notable project. For a GitHub project that means at least **75 stars, 30 forks
or 30 watchers**, and **225 stars, 90 forks or 90 watchers** when the author
submits it. The name `tcpcat` is free there, the license (AGPL-3.0) is
accepted, and the code builds from source without cgo, so notability is the
only blocker.

When the threshold is met, the core formula must build from source rather than
install the release binaries:

```ruby
class Tcpcat < Formula
  desc "Network scanner with an AF_XDP engine, service detection and CVE lookup"
  homepage "https://tcpcat.io"
  url "https://github.com/NycolazSec/tcpcat/archive/refs/tags/vX.Y.Z.tar.gz"
  sha256 "..."
  license "AGPL-3.0-only"

  depends_on "go" => :build

  def install
    ldflags = "-s -w -X main.version=#{version}"
    system "go", "build", *std_go_args(ldflags:), "./cmd/tcpcat"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tcpcat --version")
  end
end
```

Check it with `brew audit --new --strict --online tcpcat` and
`brew install --build-from-source tcpcat` before opening the pull request on
[Homebrew/homebrew-core](https://github.com/Homebrew/homebrew-core).

## AUR (`tcpcat-bin`) — ready, currently off

The `aurs:` block in `.goreleaser.yaml` is written but commented out.

1. Create an account on https://aur.archlinux.org and add an SSH public key.
2. Register the package name `tcpcat-bin` (first push creates it).
3. Add your AUR SSH **private** key as the repo secret `AUR_KEY`.
4. Uncomment the `aurs:` block in `.goreleaser.yaml` and the `AUR_KEY` line in
   the release workflow.
5. Tag a release.

## BlackArch — live

tcpcat has been in BlackArch since October 2026
([BlackArch/blackarch#5114](https://github.com/BlackArch/blackarch/pull/5114)):
`pacman -S tcpcat`. The package's PKGBUILD lives in the BlackArch tree, at
`packages/tcpcat/PKGBUILD`.
[`packaging/blackarch/PKGBUILD`](../packaging/blackarch/PKGBUILD) is a copy,
kept in sync with it.

It is a git package. When BlackArch rebuilds it, it builds `main` as it is
then, not the latest release. BlackArch bumps its git packages in batches,
every few weeks. The build stamps the version, so `tcpcat --version` prints,
for example, `1.10.0.r0.g1234abc`.

To ship a release sooner, or to change the package (description, license,
dependencies):

1. Open a pull request on
   [BlackArch/blackarch](https://github.com/BlackArch/blackarch) that edits
   `packages/tcpcat/PKGBUILD`.
2. In it, set `pkgver` to what this prints on `main`, and reset `pkgrel` to 1:

   ```bash
   git describe --long --tags --abbrev=7 | sed 's/\([^-]*-g\)/r\1/;s/-/./g'
   ```

3. Copy the file here.

To see which version `pacman` installs, read the repository database. The
tools page on blackarch.org lags behind it.

```bash
curl -sL https://www.blackarch.org/blackarch/blackarch/os/x86_64/blackarch.db |
  tar -tz | grep -m1 '^tcpcat-v'
```

There is no aarch64 build yet.

## Testing the config without publishing

GoReleaser can run the whole pipeline locally without pushing anything:

```bash
goreleaser release --snapshot --clean --skip=publish,sign
```

This builds the binaries, packages, and the Docker image so you can catch
config errors before tagging a real release.
