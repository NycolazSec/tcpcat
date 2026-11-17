#!/bin/bash
set -euo pipefail

VERSION="${VERSION:-1.0.1}"
OUTPUT_DMG="tcpcat-v${VERSION}.dmg"
OUTPUT_PKG="tcpcat-v${VERSION}.pkg"

echo "[*] Cleaning previous macOS build outputs..."
rm -rf build "${OUTPUT_DMG}" "${OUTPUT_PKG}"
mkdir -p build/bin build/pkg-root/usr/local/bin build/dmg-source

# Stamp the binary like GoReleaser does (.goreleaser.yaml), so `tcpcat
# --version` from the installer reports the release, not "dev".
COMMIT="${COMMIT:-$(git rev-parse HEAD 2>/dev/null || echo none)}"
DATE="${DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}"

echo "[*] Building universal macOS binary (${VERSION}, ${COMMIT})..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="${LDFLAGS}" -o build/bin/tcpcat-arm64 ./cmd/tcpcat
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="${LDFLAGS}" -o build/bin/tcpcat-amd64 ./cmd/tcpcat
lipo -create -output build/bin/tcpcat build/bin/tcpcat-arm64 build/bin/tcpcat-amd64
chmod +x build/bin/tcpcat

echo "[*] Creating macOS installer package..."
cp build/bin/tcpcat build/pkg-root/usr/local/bin/
pkgbuild --root build/pkg-root \
    --identifier com.nycolazsec.tcpcat \
    --version "${VERSION}" \
    --install-location / \
    "${OUTPUT_PKG}"
cp "${OUTPUT_PKG}" build/dmg-source/Install-tcpcat.pkg

echo "[*] Creating disk image..."
# On GitHub's macOS runners, hdiutil intermittently fails with "create
# failed - Resource busy" (v1.6.0's installer build did); the same command
# goes through a few seconds later.
for attempt in 1 2 3 4 5; do
    if hdiutil create -volname "tcpcat ${VERSION}" \
        -srcfolder build/dmg-source \
        -ov -format UDZO \
        "${OUTPUT_DMG}"; then
        break
    fi
    if [ "${attempt}" -eq 5 ]; then
        echo "[-] hdiutil create failed ${attempt} times; giving up." >&2
        exit 1
    fi
    echo "[!] hdiutil create failed (attempt ${attempt}/5); retrying in $((attempt * 5)) s..." >&2
    sleep $((attempt * 5))
done

echo "[+] Created ${OUTPUT_DMG}"
echo "[+] Created ${OUTPUT_PKG}"