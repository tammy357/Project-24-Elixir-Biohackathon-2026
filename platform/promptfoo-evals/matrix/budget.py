"""The approved plan and the hard agent-run budget, enforced inside the providers.

build_suite.py / build_replay.py write a generated promptfoo config and a plan next to it
(`<config>.plan.json`): the config's sha256, the agent-run limit and the counts behind it. A
provider runs only when

  - MATRIX_APPROVE holds the plan's hash (the human read the dry-run numbers and approved them),
  - the config on disk still has that hash (nothing changed after the approval), and
  - the ledger (`<config>.ledger.json`) has room: every agent run counts once, across reruns of the
    same plan, so a retried or repeated eval cannot exceed what was approved.

Following the design of evaluation-loop (J. Augustin): nothing reaches the agent without an
approved plan, and the budget is checked per call, not per eval. A new plan (any config change)
has a new hash and a new ledger; to run the same plan again from zero, delete its ledger.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import time
from pathlib import Path


class PlanError(Exception):
    pass


def config_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def plan_path(config: Path) -> Path:
    return config.with_name(config.name + ".plan.json")


def ledger_path(config: Path) -> Path:
    return config.with_name(config.name + ".ledger.json")


def write_plan(config: Path, *, max_agent_runs: int, counts: dict) -> dict:
    plan = {"config": config.name, "sha256": config_hash(config), "max_agent_runs": int(max_agent_runs),
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **counts}
    plan_path(config).write_text(json.dumps(plan, indent=2) + "\n")
    return plan


def check_plan(plan_file: str) -> dict:
    """The plan, if it is approved and unchanged; else PlanError with the reason."""
    p = Path(plan_file)
    try:
        plan = json.loads(p.read_text())
    except (OSError, ValueError) as e:
        raise PlanError(f"no readable plan at {p.name}: build the suite with build_suite.py") from e
    approved = os.environ.get("MATRIX_APPROVE", "").strip()
    if not approved:
        raise PlanError(f"not approved: set MATRIX_APPROVE={plan['sha256'][:12]}... after reading the dry run")
    if not plan["sha256"].startswith(approved) or len(approved) < 12:
        raise PlanError("MATRIX_APPROVE does not match this plan's hash (at least its first 12 characters)")
    config = p.with_name(plan["config"])
    try:
        if config_hash(config) != plan["sha256"]:
            raise PlanError(f"{config.name} changed after the plan was written: rebuild and approve again")
    except OSError as e:
        raise PlanError(f"cannot read {config.name}") from e
    return plan


def take_run(plan_file: str) -> tuple[bool, int, int]:
    """Count one agent run against the plan's budget. Returns (allowed, used, limit)."""
    p = Path(plan_file)
    plan = json.loads(p.read_text())
    limit = int(plan["max_agent_runs"])
    ledger = p.with_name(plan["config"] + ".ledger.json")
    with open(ledger, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.seek(0)
        try:
            state = json.loads(f.read() or "{}")
        except ValueError:
            state = {}
        if state.get("sha256") not in (None, plan["sha256"]):
            state = {}  # a ledger of an older plan under the same name: start over
        used = int(state.get("agent_runs", 0))
        if used >= limit:
            return False, used, limit
        state = {"sha256": plan["sha256"], "agent_runs": used + 1, "limit": limit}
        f.seek(0)
        f.truncate()
        f.write(json.dumps(state))
        return True, used + 1, limit
