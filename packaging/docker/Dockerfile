# Release image, built by GoReleaser (see .goreleaser.yaml `dockers:`).
# GoReleaser drops the already-built, static `tcpcat` binary into the build
# context, so this stage only needs a small runtime base -- no Go toolchain.
FROM alpine:3.21

# ca-certificates: HTTPS calls to CVE feeds (OSV / Vulners).
# iputils + libcap: ICMP host discovery and capability-based (non-root) runs.
RUN apk add --no-cache ca-certificates iputils libcap

COPY tcpcat /usr/bin/tcpcat

# tcpcat opens raw sockets, so it needs NET_RAW/NET_ADMIN (and more for the
# eBPF/AF_XDP engine). Grant them at run time, e.g.:
#   docker run --rm --cap-add=NET_RAW --cap-add=NET_ADMIN \
#     ghcr.io/nycolazsec/tcpcat:latest -sV -p 22,80,443 scanme.nmap.org
# The eBPF engine (--ebpf) additionally needs `--privileged` or
# CAP_BPF/CAP_SYS_ADMIN plus a host network namespace (`--network=host`).
ENTRYPOINT ["/usr/bin/tcpcat"]
