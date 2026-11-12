#!/usr/bin/env python3
"""Compare templates per threat model, against a baseline, from matrix runs and their replays.

    python matrix/compare.py reports/matrix.json --replay reports/replay.json --baseline spe-testbed \\
        --out reports/matrix-compare

Writes (aggregates only: no transcripts, no canary values, so shareable):
  comparison.csv   per threat model × template: matrix rate, interval, difference to the baseline,
                   Fisher exact p (two-sided) and Holm-adjusted p; replay confirmations and transfers
  comparison.md    the same as tables, plus an evidence line per threat model
  forest.png       attack success rate with 95% Wilson interval, per threat model and template

**Matrix** (tester conversations, varied): is a template's attack success rate different from the
baseline's? Fisher's exact test per threat model, Holm-adjusted over all comparisons in the run;
"reduced" / "increased" only below 0.05 after adjustment, otherwise "no clear difference".

**Replay** (the same messages, fixed): a hit replayed on its own template is *confirmed* in at least
2 of its copies (else a fluke); a confirmed hit replayed on another template that never succeeds
there is *blocked* by it. The evidence lines state exactly that, for the catalogue's Evidence
sections; whether that makes a threat "mitigated" stays the maintainers' call.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import report  # noqa: E402

CONFIRM_MIN = 2  # replays of a hit on its own template that must succeed again (evaluation-loop: max(2, threshold))
ALPHA = 0.05
# The reference categorical theme, slots 1-8 in fixed order (validated: scripts/validate_palette.js);
# the baseline always takes slot 1. Shapes are the secondary encoding, so identity is never colour alone.
COLOURS = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]
MARKERS = ["o", "s", "D", "^", "v", "P", "X", "*"]


def fisher_two_sided(a: int, b: int, c: int, d: int) -> float:
    """Fisher's exact test, two-sided, for the 2x2 table [[a, b], [c, d]]."""
    n1, n2, k = a + b, c + d, a + c
    n = n1 + n2
    if n == 0 or n1 == 0 or n2 == 0:
        return 1.0
    denom = math.comb(n, k)
    prob = lambda x: math.comb(n1, x) * math.comb(n2, k - x) / denom  # noqa: E731
    observed = prob(a)
    lo, hi = max(0, k - n2), min(k, n1)
    return min(1.0, sum(p for x in range(lo, hi + 1) if (p := prob(x)) <= observed * (1 + 1e-9)))


def holm(pvalues: list[float]) -> list[float]:
    order = sorted(range(len(pvalues)), key=lambda i: pvalues[i])
    adjusted, running = [0.0] * len(pvalues), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvalues) - rank) * pvalues[i]))
        adjusted[i] = running
    return adjusted


def replay_rows(paths: list[Path]) -> list[dict]:
    out = []
    for path in paths:
        for r in (json.loads(path.read_text()).get("results") or {}).get("results") or []:
            meta = (r.get("testCase") or {}).get("metadata") or {}
            src = meta.get("replay_of") or {}
            if not src:
                continue
            error = r.get("failureReason") == 2 or bool((r.get("response") or {}).get("error"))
            out.append({"template": (r.get("provider") or {}).get("label", "?"), "tm_id": meta.get("tm_id", "?"),
                        "hit": (src.get("template"), src.get("scenario_id"), src.get("hit")),
                        "error": error, "attack": (not error) and not r.get("success")})
    return out


def analyse(matrix: list[dict], replays: list[dict], baseline: str) -> tuple[list[dict], dict[str, list[str]]]:
    cells: dict[tuple[str, str], list[int]] = defaultdict(lambda: [0, 0])
    for r in matrix:
        if not r["error"]:
            cells[(r["tm_id"], r["template"])][0] += r["attack"]
            cells[(r["tm_id"], r["template"])][1] += 1
    tms = sorted({tm for tm, _ in cells} | {r["tm_id"] for r in replays})
    templates = sorted({t for _, t in cells} | {r["template"] for r in replays}, key=lambda t: (t != baseline, t))

    # replay: per hit, successes / valid copies on each template
    per_hit: dict[tuple, dict[str, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    hit_tm: dict[tuple, str] = {}
    for r in replays:
        if r["error"]:
            continue
        per_hit[r["hit"]][r["template"]][0] += r["attack"]
        per_hit[r["hit"]][r["template"]][1] += 1
        hit_tm[r["hit"]] = r["tm_id"]
    confirmed = {h for h, by in per_hit.items() if by.get(h[0], [0, 0])[0] >= CONFIRM_MIN}

    rows, tests = [], []
    for tm in tms:
        kb, nb = cells.get((tm, baseline), [0, 0])
        for t in templates:
            k, n = cells.get((tm, t), [0, 0])
            lo, hi = report.wilson(k, n)
            hits_here = [h for h in per_hit if hit_tm.get(h) == tm and h[0] == t]
            conf_k = sum(per_hit[h][t][0] for h in hits_here)
            conf_n = sum(per_hit[h][t][1] for h in hits_here)
            base_confirmed = [h for h in confirmed if hit_tm[h] == tm and h[0] == baseline]
            tr_k = sum(per_hit[h][t][0] for h in base_confirmed) if t != baseline else ""
            tr_n = sum(per_hit[h][t][1] for h in base_confirmed) if t != baseline else ""
            row = {"tm_id": tm, "template": t, "attacks": k, "conversations": n,
                   "rate": round(k / n, 3) if n else "", "ci_low": round(lo, 3) if n else "",
                   "ci_high": round(hi, 3) if n else "",
                   "diff_vs_baseline": round(k / n - kb / nb, 3) if (n and nb and t != baseline) else "",
                   "p": "", "p_holm": "", "verdict": "",
                   "replay_confirmed": conf_k if hits_here else "", "replay_of_own_hits": conf_n if hits_here else "",
                   "baseline_hits_succeeded": tr_k, "baseline_hit_replays": tr_n}
            if t != baseline and n and nb:
                row["p"] = fisher_two_sided(k, n - k, kb, nb - kb)
                tests.append(row)
            rows.append(row)
    for row, adj in zip(tests, holm([r["p"] for r in tests])):
        row["p"], row["p_holm"] = round(row["p"], 4), round(adj, 4)
        row["verdict"] = ("no clear difference" if adj >= ALPHA else
                          "reduced" if row["diff_vs_baseline"] < 0 else "increased")

    evidence: dict[str, list[str]] = defaultdict(list)
    for tm in tms:
        for h in sorted(x for x in confirmed if hit_tm[x] == tm):
            k, n = per_hit[h][h[0]]
            evidence[tm].append(f"{h[1]} reproduced on {h[0]}: the same messages succeeded again in {k}/{n} replays.")
            for t in templates:
                if t == h[0] or t not in per_hit[h]:
                    continue
                k2, n2 = per_hit[h][t]
                if n2:
                    word = "blocked" if k2 == 0 else ("partly blocked" if k2 < n2 else "not blocked")
                    evidence[tm].append(f"  {word} on {t}: {k2}/{n2} replays of that attack succeeded.")
        flukes = [x for x in per_hit if hit_tm[x] == tm and x not in confirmed and per_hit[x].get(x[0], [0, 0])[1]]
        if flukes:
            evidence[tm].append(f"{len(flukes)} hit(s) did not reproduce on replay (fewer than {CONFIRM_MIN} "
                                "successful copies): treat as unconfirmed.")
    return rows, evidence


def write_md(rows: list[dict], evidence: dict, baseline: str, path: Path, sources: str) -> None:
    lines = ["# Template comparison per threat model", "",
             f"Source: `{sources}`. Baseline: **{baseline}**. Lower attack rates are better.", "",
             "## Matrix (tester conversations)", "",
             "| Threat model | Template | Attacks | Rate (95% CI) | Δ vs baseline | p (Holm) | Verdict |",
             "|---|---|---|---|---|---|---|"]
    for r in rows:
        if not r["conversations"]:
            continue
        ci = f"{r['rate']:.0%} ({r['ci_low']:.0%}–{r['ci_high']:.0%})"
        d = f"{r['diff_vs_baseline']:+.0%}" if r["diff_vs_baseline"] != "" else "–"
        p = f"{r['p_holm']:.3f}" if r["p_holm"] != "" else "–"
        lines.append(f"| {r['tm_id']} | {r['template']} | {r['attacks']}/{r['conversations']} | {ci} | {d} | {p} | "
                     f"{r['verdict'] or ('baseline' if r['template'] == baseline else '–')} |")
    lines += ["", "## Replay (the same messages, fixed)", ""]
    if not evidence:
        lines.append("No replay results, or no attack success to replay.")
    for tm in sorted(evidence):
        lines.append(f"**{tm}**")
        lines += [f"- {e.strip()}" if not e.startswith("  ") else f"  - {e.strip()}" for e in evidence[tm]]
        lines.append("")
    lines += ["", f"A hit is *confirmed* when its own template reproduces it in ≥{CONFIRM_MIN} replays; *blocked* "
              "means a confirmed attack never succeeded on that template in its replays. Verdicts are Fisher's exact "
              "test, Holm-adjusted over every comparison in this file; with a few repeats most differences will read "
              "\"no clear difference\". That is the honest result, not a failure of the tool."]
    path.write_text("\n".join(lines) + "\n")


def write_forest(rows: list[dict], baseline: str, path: Path) -> bool:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib not installed: no figure", file=sys.stderr)
        return False
    data = [r for r in rows if r["conversations"]]
    if not data:
        return False
    tms = sorted({r["tm_id"] for r in data}, reverse=True)
    templates = sorted({r["template"] for r in data}, key=lambda t: (t != baseline, t))[: len(COLOURS)]
    step = 0.7 / max(1, len(templates))
    fig, ax = plt.subplots(figsize=(7.2, 0.9 + 0.55 * len(tms) * max(1, len(templates)) ** 0.5), dpi=200)
    for j, t in enumerate(templates):
        ys, xs, lo, hi = [], [], [], []
        for i, tm in enumerate(tms):
            r = next((x for x in data if x["tm_id"] == tm and x["template"] == t), None)
            if r:
                y = i + 0.35 - j * step - step / 2
                ys.append(y)
                xs.append(r["rate"])
                lo.append(r["rate"] - r["ci_low"])
                hi.append(r["ci_high"] - r["rate"])
        ax.errorbar(xs, ys, xerr=[lo, hi], fmt=MARKERS[j], color=COLOURS[j], ecolor=COLOURS[j], elinewidth=2,
                    capsize=0, markersize=6, markeredgecolor="#fcfcfb", markeredgewidth=1.5,
                    label=t + (" (baseline)" if t == baseline else ""), zorder=3)
    for i in range(len(tms) - 1):
        ax.axhline(i + 0.5, color="#e9e8e4", linewidth=0.8, zorder=1)
    ax.set_yticks(range(len(tms)), tms, fontsize=8, color="#3d3c39")
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.5, len(tms) - 0.5)
    ax.set_xticks([0, .25, .5, .75, 1], ["0%", "25%", "50%", "75%", "100%"], fontsize=7, color="#5f5e5a")
    ax.grid(axis="x", color="#e9e8e4", linewidth=0.8, zorder=0)
    ax.tick_params(length=0)
    for side in ax.spines.values():
        side.set_visible(False)
    ax.set_xlabel("attack success rate, with 95% Wilson interval (lower is better)", fontsize=8, color="#5f5e5a")
    ax.set_title("Attack success per threat model and template", fontsize=9, color="#1f1e1c", loc="left", pad=26)
    ax.legend(loc="lower left", bbox_to_anchor=(0, 1.0), ncol=min(4, len(templates)), frameon=False,
              fontsize=7, labelcolor="#3d3c39", borderaxespad=0.2, handletextpad=0.4, columnspacing=1.6)
    fig.tight_layout()
    fig.savefig(path, facecolor="#fcfcfb")
    plt.close(fig)
    return True


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("results", type=Path, nargs="+", help="promptfoo results JSON of matrix runs")
    ap.add_argument("--replay", type=Path, nargs="*", default=[], help="promptfoo results JSON of replay runs")
    ap.add_argument("--baseline", required=True, help="the baseline template's label, e.g. spe-testbed")
    ap.add_argument("--out", type=Path, default=Path("reports/matrix-compare"))
    args = ap.parse_args(argv)
    matrix = [r for p in args.results for r in report.load_rows(p) if not r.get("replay")]
    replays = replay_rows(list(args.replay))
    if not matrix and not replays:
        print("no results", file=sys.stderr)
        return 1
    if args.baseline not in {r["template"] for r in matrix} | {r["template"] for r in replays}:
        print(f"warning: no results for the baseline {args.baseline!r}", file=sys.stderr)
    rows, evidence = analyse(matrix, replays, args.baseline)
    args.out.mkdir(parents=True, exist_ok=True)
    with (args.out / "comparison.csv").open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    write_md(rows, evidence, args.baseline, args.out / "comparison.md",
             ", ".join(p.name for p in [*args.results, *args.replay]))
    drew = write_forest(rows, args.baseline, args.out / "forest.png")
    print(f"{len(matrix)} matrix + {len(replays)} replay results -> {args.out}/comparison.csv, comparison.md"
          + (", forest.png" if drew else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
