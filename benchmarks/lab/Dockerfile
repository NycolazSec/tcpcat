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
RUN CGO_ENABLED=0 go build -trimpath -o /out/tcpcat ./cmd/tcpcat

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      nmap hyperfine jq iproute2 ethtool pciutils libpcap0.8 python3 ca-certificates procps \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/tcpcat /usr/local/bin/tcpcat
COPY --from=build /go/bin/naabu /usr/local/bin/naabu
COPY benchmarks/lab/inside.sh benchmarks/lab/report.py /bench/
WORKDIR /bench
ENTRYPOINT ["/bench/inside.sh"]
