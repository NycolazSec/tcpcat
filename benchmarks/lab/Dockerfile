# Scanner image for benchmarks/run.sh: tcpcat built from this checkout, next
# to the tools it is compared with. Versions are recorded in every report.
FROM golang:1.26-bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev && rm -rf /var/lib/apt/lists/*
ARG NAABU_VERSION=latest
RUN go install github.com/projectdiscovery/naabu/v2/cmd/naabu@${NAABU_VERSION}
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Stamped like a release build (.goreleaser.yaml), so the report names the
# tcpcat being measured instead of "dev". run.sh passes the values.
ARG TCPCAT_VERSION=dev
ARG TCPCAT_COMMIT=none
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${TCPCAT_VERSION} -X main.commit=${TCPCAT_COMMIT} -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      -o /out/tcpcat ./cmd/tcpcat

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap masscan hyperfine jq iproute2 ethtool pciutils libpcap0.8 python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/tcpcat /usr/local/bin/tcpcat
COPY --from=build /go/bin/naabu /usr/local/bin/naabu
COPY benchmarks/lab/inside.sh benchmarks/lab/report.py /bench/
WORKDIR /bench
ENTRYPOINT ["/bench/inside.sh"]
