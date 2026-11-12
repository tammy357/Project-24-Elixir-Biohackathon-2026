#!/usr/bin/env python3
"""Build the replay suite: every attack success of a matrix run, replayed unchanged on every template.

    python matrix/build_replay.py reports/matrix.json --targets matrix/targets.yaml --copies 3
    export MATRIX_APPROVE=<hash printed above>
    npx promptfoo eval -c matrix/matrix.replay.yaml --no-cache --no-share -o reports/replay.json
    python matrix/compare.py reports/matrix.json --replay reports/replay.json --baseline spe-testbed

For each failed test (an attack success, not an error) the tester's user messages are taken from
the results and replayed, with no tester model, `--copies` times on every target:

  - on the **template where it succeeded**: confirmation. Did the same messages work again, or was
    it a lucky conversation? (evaluation-loop's replay idea, J. Augustin)
  - on **every other template**: transfer. Does a protection block an attack known to work on the
    baseline? This is the controlled comparison behind "mitigated".

Replays carry the original assertions, so they are scored the same way. The replay config holds
the tester's messages: as private as the results it came from. Never commit or share it.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import budget  # noqa: E402
import build_suite  # noqa: E402


def hits(paths: list[Path], sources: set[str], per_scenario: int) -> list[dict]:
    """Attack successes with a recorded conversation, at most `per_scenario` per template and scenario."""
    taken: dict[tuple[str, str], int] = defaultdict(int)
    out = []
    for path in paths:
        rows = (json.loads(path.read_text()).get("results") or {}).get("results") or []
        for r in rows:
            if r.get("success") or r.get("failureReason") == 2:
                continue
            meta = (r.get("response") or {}).get("metadata") or {}
            if meta.get("replay_of"):
                continue  # never replay a replay
            turns = [t.get("user") for t in meta.get("turns") or [] if t.get("user")]
            label = (r.get("provider") or {}).get("label", "")
            tmeta = (r.get("testCase") or {}).get("metadata") or {}
            sid = tmeta.get("scenario_id") or (r.get("vars") or {}).get("scenario_id", "")
            if not turns or (sources and label not in sources) or taken[(label, sid)] >= per_scenario:
                continue
            taken[(label, sid)] += 1
            out.append({"source": label, "scenario_id": sid, "n": taken[(label, sid)], "turns": turns,
                        "vars": r.get("vars") or {}, "metadata": tmeta,
                        "assert": (r.get("testCase") or {}).get("assert") or []})
    return out


def build_tests(found: list[dict]) -> list[dict]:
    tests = []
    for h in found:
        replay_of = {"template": h["source"], "scenario_id": h["scenario_id"], "hit": h["n"]}
        vars_ = {k: v for k, v in h["vars"].items() if k not in ("replay_turns", "replay_of")}
        tests.append({
            "description": f"replay {h['scenario_id']} from {h['source']} #{h['n']}",
            # one JSON string: promptfoo expands a list-valued var into one test per item
            "vars": {**vars_, "replay_turns": json.dumps(h["turns"]), "replay_of": replay_of},
            "metadata": {**h["metadata"], "replay_of": replay_of},
            "assert": h["assert"],
        })
    return tests


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results", type=Path, nargs="+", help="promptfoo results JSON of matrix runs")
    ap.add_argument("--targets", type=Path, required=True, help="the targets file (fresh workspaces)")
    ap.add_argument("--copies", type=int, default=3, help="replays of each hit on each target")
    ap.add_argument("--sources", default="", help="replay only hits from these labels (default: all)")
    ap.add_argument("--per-scenario", type=int, default=1, help="hits per template and scenario to replay")
    ap.add_argument("--max-agent-runs", type=int, default=None)
    ap.add_argument("--out", type=Path, default=HERE / "matrix.replay.yaml")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    spec = yaml.safe_load(args.targets.read_text()) or {}
    targets = spec.get("targets") or []
    if not targets:
        ap.error(f"{args.targets}: no targets")
    sources = {s.strip() for s in args.sources.split(",") if s.strip()}
    found = hits(args.results, sources, args.per_scenario)
    turns = sum(len(h["turns"]) for h in found)
    runs = turns * len(targets) * args.copies
    max_runs = min(runs, args.max_agent_runs) if args.max_agent_runs else runs
    print(f"{len(found)} hits to replay ({', '.join(sorted({h['scenario_id'] for h in found})) or 'none'}), "
          f"{len(targets)} targets, {args.copies} copies: {len(found) * len(targets) * args.copies} replays, "
          f"{runs} agent runs, no tester calls; budget {max_runs}", file=sys.stderr)
    if not found or args.dry_run:
        return 0

    defaults = {"tester": {}, "plan_file": str(budget.plan_path(args.out.resolve()))}
    if spec.get("protected_names"):
        defaults["protected_names"] = [n.strip() for n in spec["protected_names"]]
    config = {
        "description": "Threat-model matrix: replay of attack successes on every template (build_replay.py)",
        "prompts": ["{{scenario_id}}"],
        "providers": build_suite.build_providers(targets, defaults, args.targets.resolve().parent,
                                                 provider=f"file://{HERE / 'replay_provider.py'}"),
        "defaultTest": {"options": {"provider": spec.get("judge")}} if spec.get("judge") else {},
        "evaluateOptions": {"maxConcurrency": int(spec.get("max_concurrency", 1)), "repeat": args.copies},
        "tests": build_tests(found),
    }

    class _NoAliases(yaml.SafeDumper):
        def ignore_aliases(self, data):
            return True

    args.out.write_text("# Generated by build_replay.py: holds the tester's messages. Private: never commit or share.\n"
                        + yaml.dump(config, Dumper=_NoAliases, sort_keys=False, allow_unicode=True, width=120))
    plan = budget.write_plan(args.out, max_agent_runs=max_runs, counts={
        "kind": "replay", "hits": len(found), "targets": [t["label"] for t in targets],
        "copies": args.copies, "replays": len(found) * len(targets) * args.copies})
    print(f"wrote {args.out} and its plan\napprove after checking the numbers above:  "
          f"export MATRIX_APPROVE={plan['sha256'][:16]}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
