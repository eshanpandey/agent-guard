"""Run Agent Guard against public agent-safety benchmarks.

    python eval/run_eval.py --label v0.1 --split all

Writes eval/results/<label>.json and prints a summary table.
"""

from __future__ import annotations

import argparse
import json
import pickle
import platform
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE / "adapters")]

from common import dump, evaluate  # noqa: E402

CACHE = HERE / ".data" / "traces"


def traces_for(name: str):
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / f"{name}.pkl"
    if path.exists():
        return pickle.loads(path.read_bytes())
    if name.startswith("agentdojo"):
        from agentdojo_adapter import load
        traces = load(attack=name.split(":", 1)[1])
    elif name.startswith("injecagent"):
        from injecagent_adapter import load
        traces = load(setting=name.split(":", 1)[1])
    elif name == "rjudge":
        from rjudge_adapter import load
        traces = load()
    else:
        raise ValueError(name)
    path.write_bytes(pickle.dumps(traces))
    return traces


DATASETS = ["agentdojo:important_instructions", "agentdojo:direct", "injecagent:base", "injecagent:enhanced", "rjudge"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--label", required=True)
    ap.add_argument("--split", choices=["dev", "test", "all"], default="dev")
    ap.add_argument("--datasets", nargs="*", default=DATASETS)
    ap.add_argument("--no-user-prompt", action="store_true", help="Do not give the guard the user's prompt.")
    args = ap.parse_args()
    import common
    common.USE_USER_PROMPT = not args.no_user_prompt

    import agentguard
    out = {"label": args.label, "split": args.split, "agentguard_version": agentguard.__version__,
           "python": platform.python_version(), "machine": platform.machine(), "processor": platform.processor(),
           "user_prompt_visible": not args.no_user_prompt, "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "datasets": {}}
    for name in args.datasets:
        traces = traces_for(name)
        if args.split != "all":
            traces = [t for t in traces if t.split == args.split]
        res = evaluate(traces)
        out["datasets"][name] = {k: v for k, v in res.items() if not k.startswith("_")}
        unit = "trace" if name == "rjudge" else "call"
        print(f"\n{name}  ({res['traces']} traces, {res['harmful_traces']} harmful, {res['malicious_calls']} malicious calls)")
        print(f"  {'threshold':<9} {'unit':<5} {'prec':>6} {'recall':>6} {'F1':>6} {'FPR':>6}   trace-recall trace-FPR")
        for th, m in res["by_threshold"].items():
            c = m[unit]
            t = m["trace"]
            print(f"  {th:<9} {unit:<5} {c['precision']:>6.3f} {c['recall']:>6.3f} {c['f1']:>6.3f} {c['fpr']:>6.3f}   "
                  f"{t['recall']:>6.3f}       {t['fpr']:>6.3f}")
        lat = res["latency"]
        print(f"  latency per call: p50 {lat['p50_us']} us, p95 {lat['p95_us']} us, p99 {lat['p99_us']} us")
    (HERE / "results").mkdir(exist_ok=True)
    path = HERE / "results" / f"{args.label}-{args.split}.json"
    path.write_text(json.dumps(out, indent=2))
    print(f"\nwrote {path}")


if __name__ == "__main__":
    main()
