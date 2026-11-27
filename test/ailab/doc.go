// Package ailab is a lab of hardened machines for tcpcat's AI.
//
// Each scenario builds a target machine in its own Linux network namespace:
// real nftables rules (an allow-list firewall, ICMP rejects, a ban after a
// scan, a rate limit), and small services from ./labsrv (a slow SSH banner,
// services that accept and stay silent, an SSH tarpit). tcpcat scans it from
// a second namespace with --ai-deep, and the test checks that the AI names
// each defense, and does not mistake one for another.
//
// It needs Linux, root, iproute2 and nft, and builds nothing as root:
//
//	go build -o /tmp/ailab/tcpcat ./cmd/tcpcat
//	go build -o /tmp/ailab/labsrv ./test/ailab/labsrv
//	go test -c -tags ailab -o /tmp/ailab/ailab.test ./test/ailab
//	sudo TCPCAT_BIN=/tmp/ailab/tcpcat LABSRV_BIN=/tmp/ailab/labsrv /tmp/ailab/ailab.test -test.v
//
// The namespaces, their interfaces and rules disappear when a scenario ends;
// nothing outside them is touched.
package ailab
