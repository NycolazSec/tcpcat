# 1. Installer dpkg sur Mac (si pas encore fait)
brew install dpkg

# 2. Préparer l'arborescence du paquet Debian
VERSION="1.0.1"
DEB_DIR="build/deb/tcpcat_${VERSION}_amd64"
mkdir -p "${DEB_DIR}/DEBIAN"
mkdir -p "${DEB_DIR}/usr/local/bin"

# 3. Compiler le binaire Linux
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${DEB_DIR}/usr/local/bin/tcpcat" ./cmd/tcpcat
chmod +x "${DEB_DIR}/usr/local/bin/tcpcat"

# 4. Créer le fichier de contrôle DEBIAN
cat << CONTROL > "${DEB_DIR}/DEBIAN/control"
Package: tcpcat
Version: ${VERSION}
Section: net
Priority: optional
Architecture: amd64
Maintainer: NycolazSec <contact@nycolazsec.com>
Description: High-Performance Network Reconnaissance & Vulnerability Intelligence Platform
CONTROL

# 5. Créer le paquet .deb
dpkg-deb --build "${DEB_DIR}" "tcpcat_${VERSION}_amd64.deb"