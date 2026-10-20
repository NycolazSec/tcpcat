"""Benchmark target: listens on a fixed, reproducible set of TCP ports.

The set is derived from SEED and COUNT only, so every run of the benchmark
(and anyone re-running it) scans the same ground truth. Connections are
accepted and closed at once: the scanners are measured on finding open
ports, not on talking to services.
"""
import asyncio
import os
import random

SEED = int(os.environ.get("SEED", "1337"))
COUNT = int(os.environ.get("COUNT", "40"))


def ports() -> list[int]:
    rng = random.Random(SEED)
    well_known = [22, 80, 443, 3306, 5432, 6379, 8080, 8443]
    chosen = set(well_known)
    while len(chosen) < COUNT:
        chosen.add(rng.randrange(1, 65536))
    return sorted(chosen)


async def handle(_reader, writer):
    writer.close()


async def main():
    servers = [await asyncio.start_server(handle, "0.0.0.0", p, backlog=1024) for p in ports()]
    print(" ".join(map(str, ports())), flush=True)
    await asyncio.gather(*(s.serve_forever() for s in servers))


if __name__ == "__main__":
    if os.environ.get("PRINT_PORTS"):
        print(" ".join(map(str, ports())))
    else:
        asyncio.run(main())
