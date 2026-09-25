#!/bin/bash
set -euo pipefail

VERSION="${VERSION:-1.0.1}"
OUTPUT_DMG="tcpcat-v${VERSION}.dmg"
OUTPUT_PKG="tcpcat-v${VERSION}.pkg"

echo "[*] Cleaning previous macOS build outputs..."
rm -rf build "${OUTPUT_DMG}" "${OUTPUT_PKG}"
mkdir -p build/bin build/pkg-root/usr/local/bin build/dmg-source

echo "[*] Building universal macOS binary..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o build/bin/tcpcat-arm64 ./cmd/tcpcat
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o build/bin/tcpcat-amd64 ./cmd/tcpcat
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
hdiutil create -volname "tcpcat ${VERSION}" \
    -srcfolder build/dmg-source \
    -ov -format UDZO \
    "${OUTPUT_DMG}"

echo "[+] Created ${OUTPUT_DMG}"
echo "[+] Created ${OUTPUT_PKG}"