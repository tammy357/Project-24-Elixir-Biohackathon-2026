"""promptfoo Python provider: replay a recorded conversation's user turns, unchanged, to one workspace.

No tester model: the messages are fixed (vars.replay_turns, from build_replay.py), so every copy and
every template gets exactly the same attack. That separates a reproducible weakness from a lucky
conversation, and makes the comparison between templates a controlled one. The same plan, budget
and metadata as conversation_provider.py, so the same assertions score it.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import conversation_provider  # noqa: E402


def call_api(prompt: str, options: dict | None = None, context: dict | None = None) -> dict:
    config = dict((options or {}).get("config") or {})
    vars_ = (context or {}).get("vars") or {}
    raw = vars_.get("replay_turns") or "[]"
    try:
        turns = json.loads(raw) if isinstance(raw, str) else raw
    except ValueError:
        return {"error": "replay: replay_turns is not a JSON list"}
    if not isinstance(turns, list):
        return {"error": "replay: replay_turns is not a JSON list"}
    replay = [str(m) for m in turns if str(m).strip()]
    if not replay:
        return {"error": "replay: no replay_turns in this test"}
    config["max_turns"] = len(replay)

    def next_message(turns):
        return replay[len(turns)] if len(turns) < len(replay) else None

    res = conversation_provider.converse(config, next_message, kind="replay")
    if "metadata" in res and "error" not in res:
        res["metadata"]["replay_of"] = vars_.get("replay_of") or {}
    return res
