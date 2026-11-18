"""Run three repeatable NS-2 cases and summarize the TCP trace."""

import argparse
import csv
import subprocess
from pathlib import Path

from .support import LAB

CASES = (("baseline", 5, 0), ("higher_delay", 75, 0), ("packet_loss", 5, 0.03))
SEED = 741
DURATION = 10.0


def metrics(path):
    delivered = {}
    sent = set()
    retransmissions = drops = 0
    with path.open() as trace:
        for line in trace:
            event, _, source, dest, kind, size, *extra = line.split()
            if kind != "tcp":
                continue
            seq = extra[4]
            if event == "+" and (source, dest) == ("0", "1"):
                retransmissions += seq in sent
                sent.add(seq)
            elif event == "r" and (source, dest) == ("1", "2"):
                delivered.setdefault(seq, int(size))
            elif event == "d" and (source, dest) == ("1", "2"):
                drops += 1
    return {
        "unique_packets_received": len(delivered),
        "unique_tcp_bytes": sum(delivered.values()),
        "throughput_kbps": round(sum(delivered.values()) * 8 / DURATION / 1000, 2),
        "retransmissions": retransmissions,
        "bottleneck_drops": drops,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default=Path("/results"), type=Path)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    rows = []
    for name, delay, loss in CASES:
        path = args.out / f"{name}.tr"
        subprocess.run(
            ["ns", str(LAB / "tcp.tcl"), str(delay), str(loss), str(SEED), str(path)],
            check=True,
        )
        rows.append(
            {
                "case": name,
                "delay_ms": delay,
                "loss_probability": loss,
                "seed": SEED,
                **metrics(path),
            }
        )
    with (args.out / "ns2-summary.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(
            f"{row['case']:14}  {row['throughput_kbps']:8.2f} kbit/s  "
            f"{row['retransmissions']:3} retransmissions  {row['bottleneck_drops']:3} drops"
        )


if __name__ == "__main__":
    main()
