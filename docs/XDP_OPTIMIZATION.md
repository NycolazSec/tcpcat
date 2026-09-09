# 🚀 XDP Performance Optimization Guide

## Contexte

Le module XDP dans tcpcat utilise eBPF pour scanner haute performance. Actuellement:
- Vitesse: 100K pps typique
- Cible: 1M pps (10x speedup)

## Optimisations Recommandées

### 1. Ring Buffer vs PERF_BUFFER
**État actuel**: PERF_BUFFER (inefficace)
**Recommandation**: Migrer vers Ring Buffer

```go
// internal/scan/xdp.go - Optimisation proposée
ringBuf, err := ebpf.NewRingBuffer()  // Au lieu de NewPerfBuffer()
```

**Gain**: ~20-30% d'amélioration en throughput

### 2. Hash Map Tuning
**État actuel**: Hash map standard
**Recommandation**: Préallouer avec taille correcte

```go
// internal/scan/xdp.c (eBPF)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);  // Préallouer pour 100K connexions
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct result));
} results_map SEC(".maps");
```

**Gain**: ~15% en réduisant les allocations

### 3. Batch Processing
**État actuel**: Traiter 1 paquet à la fois
**Recommandation**: Traiter par batch

```go
// Scanner engine - réduire overhead de boucle
const BatchSize = 1000
results := make([]Result, 0, BatchSize)
for i := 0; i < len(ips); i += BatchSize {
    batch := ips[i : min(i+BatchSize, len(ips))]
    results = append(results, engine.ScanBatch(batch)...)
}
```

**Gain**: ~25% en réduisant overhead syscall

### 4. CPU Affinity
**État actuel**: Workers sans affinity
**Recommandation**: Binder à core spécifique

```go
// internal/scan/engine.go
func (e *Engine) StartWorker(coreID int) {
    runtime.LockOSThread()
    syscall.Sched_setaffinity(0, &cpuset) // Binder au core
    defer runtime.UnlockOSThread()
    
    for job := range e.jobs {
        e.process(job)
    }
}
```

**Gain**: ~10-15% en réduisant context switches

### 5. NUMA Awareness
**Pour systèmes multi-socket**:
```go
// Allouer mémoire près du CPU qui l'utilisera
if numaSets > 1 {
    numaMemory := allocateNUMALocal(node)
    e.localBuffers[node] = numaMemory
}
```

**Gain**: ~5-20% selon architecture

## Benchmarks Actuels

```
BenchmarkEngineExecution-8     1000    100.5 ms/op
BenchmarkConcurrentScans-8      100    1000 ms/op
```

**Cibles après optimisation**:
```
BenchmarkEngineExecution-8    10000     10 ms/op    (10x)
BenchmarkConcurrentScans-8     1000    100 ms/op    (10x)
```

## Priorité d'Implementation

1. **P0 - Ring Buffer Migration** (20-30% gain, 4h)
2. **P1 - Batch Processing** (25% gain, 6h)
3. **P2 - CPU Affinity** (10-15% gain, 3h)
4. **P3 - Hash Map Tuning** (15% gain, 2h)
5. **P4 - NUMA Awareness** (5-20% gain, 8h)

## Résultat Final Attendu

- **Throughput**: 100K → 500K-1M pps
- **Latency**: 100ms → 10ms p95
- **Scalabilité**: Linear jusqu'à 16 cores
- **Mémoire**: -30% avec préallocation

## Validation

```bash
# Test de performance
go test -bench=BenchmarkEngine -benchtime=10s ./internal/scan

# Profiling
go test -cpuprofile=cpu.prof -memprofile=mem.prof ./internal/scan
go tool pprof cpu.prof

# Comparison before/after
benchstat before.txt after.txt
```

## Références

- [XDP Performance](https://www.kernel.org/doc/html/latest/networking/filter.html)
- [eBPF Ring Buffers](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
- [Go CPU Affinity](https://pkg.go.dev/runtime#LockOSThread)
- [NUMA Optimization](https://www.kernel.org/doc/Documentation/vm/numa.rst)
