# tcpcat Examples

Ce répertoire contient des exemples d'utilisation de tcpcat.

## Basic Scanner

```bash
tcpcat -target 192.168.1.1 -ports 22,80,443 -concurrency 4
```

## Scan avec Service Detection

```bash
tcpcat -target 192.168.1.1 -ports 1-1000 -service-detect -output json
```

## Scan Vulnerabilités

```bash
tcpcat -target 192.168.1.1 -ports 1-1000 -vuln-check -output json > results.json
```

## Evasion Techniques

```bash
tcpcat -target 192.168.1.1 \
  -ports 22,80,443 \
  -randomize-delay \
  -spoof-source \
  -fragment
```

## AWS VPC Scanning

```bash
tcpcat -target vpc-12345 \
  -aws-profile production \
  -service-detect \
  -output json
```

## Cloud Masscan

```bash
# Scan complet d'un range
tcpcat -targets 10.0.0.0/8 \
  -ports 1-65535 \
  -cloud-mode \
  -distributed
```

## Custom WASM Script

```javascript
// detect-custom.wasm (pseudo-code)
module.exports = {
  detect: async (service) => {
    if (service.banner.includes("CustomApp/1.0")) {
      return {
        name: "CustomApp",
        version: "1.0",
        vulns: ["CVE-2024-0001"]
      };
    }
  }
};
```

Utilisation:
```bash
tcpcat -target 192.168.1.1 -script detect-custom.wasm
```

## Benchmarking

```bash
# Mesurer performance
time tcpcat -target localhost -ports 1-10000 -concurrency 8

# Output expected (~1M pps après optimization)
# real    0m0.010s
```

## Docker

```bash
docker run --network=host -v $(pwd)/targets.txt:/targets.txt \
  tcpcat:latest \
  -targets-file /targets.txt \
  -ports 1-1000
```

## Kubernetes CronJob

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: tcpcat-scan
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: tcpcat
            image: tcpcat:latest
            args: ["-targets", "k8s-nodes", "-output", "prometheus"]
          restartPolicy: OnFailure
```

## Integration Zeek

```bash
# Export tcpcat results to Zeek
tcpcat -target 192.168.1.0/24 -output zeek-log | zeek -r -
```

## Notes

- Les exemples utilisent la CLI `tcpcat` principale
- Pour l'API Go, voir `internal/` packages
- Pour plus de détails, voir `docs/` directory
- Benchmarks complets dans `docs/XDP_OPTIMIZATION.md`

## Contribution

Pour contribuer des exemples:
1. Ajouter un exemple documenté
2. Incluire output d'exécution
3. Expliquer les cas d'usage
4. Tester sur votre machine

---

**Version**: v0.2-dev
**Dernière mise à jour**: 2024-08-28
