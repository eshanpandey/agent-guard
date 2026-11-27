"""Turn eval/results/*.json into the tables used in EVALUATION.md (with 95% Wilson intervals)."""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def pct(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{100 * k / n:.1f}% ({100 * lo:.0f}–{100 * hi:.0f})"


def row(name: str, res: dict, th: str) -> str:
    m = res["by_threshold"][th]
    t, c = m["trace"], m["call"]
    lat = res["latency"]
    rec = pct(t["tp"], t["tp"] + t["fn"])
    fpr = pct(t["fp"], t["fp"] + t["tn"])
    prec = pct(t["tp"], t["tp"] + t["fp"])
    return (f"| {name} | {res['harmful_traces']} / {res['traces'] - res['harmful_traces']} | {rec} | {fpr} | {prec} | "
            f"{t['f1']:.3f} | {c['f1']:.3f} | {lat['p50_us'] / 1000:.2f} / {lat['p99_us'] / 1000:.2f} |")


def table(label: str, th: str) -> str:
    data = json.loads((HERE / "results" / f"{label}.json").read_text())
    out = [f"**{label}**, alert threshold = {th}", "",
           "| Dataset | Harmful / benign traces | Recall (attacks caught) | FPR (benign traces flagged) | Precision | Trace F1 | Call F1 | Latency p50 / p99 (ms) |",
           "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for name, res in data["datasets"].items():
        out.append(row(name, res, th))
    return "\n".join(out)


if __name__ == "__main__":
    for label in sys.argv[1:] or ["v0.2-test", "v0.1-test", "v0.2-dev"]:
        for th in ("high", "medium"):
            print(table(label, th) + "\n")
