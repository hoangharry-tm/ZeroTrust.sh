#!/usr/bin/env python3
"""ZeroTrust.sh Python ML worker — NDJSON dispatcher over stdin/stdout.

The Go orchestrator spawns this process once at scan start and communicates
via newline-delimited JSON:
  stdin  ← {"id": "1", "type": "llm_verify", "payload": {...}}
  stdout → {"id": "1", "status": "ok", "result": {...}}
             or {"id": "1", "status": "error", "error": "..."}
"""

import json
import logging
import os
import sys
from typing import Any

from handlers import ast_edit, classify, embed, llm_scan, llm_verify, summarize

_log_level = logging.DEBUG if os.getenv("ZEROTRUST_VERBOSE") else logging.INFO
logging.basicConfig(
    level=_log_level,
    stream=sys.stderr,
    format="%(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("worker")

_HANDLERS = {
    "llm_verify": llm_verify.handle,
    "classify": classify.handle,
    "summarize": summarize.handle,
    "llm_scan": llm_scan.handle,
    "embed": embed.handle,
    "ast_edit": ast_edit.handle,
}


def _dispatch(msg: dict[str, Any]) -> dict[str, Any]:
    msg_id = msg.get("id", "")
    msg_type = msg.get("type", "")

    if msg_type == "ping":
        return {"id": msg_id, "status": "ok"}

    if msg_type == "shutdown":
        log.info("shutdown received")
        sys.exit(0)

    handler = _HANDLERS.get(msg_type)
    if handler is None:
        return {"id": msg_id, "status": "error", "error": f"unknown type: {msg_type!r}"}

    try:
        result = handler(msg.get("payload") or {})
        return {"id": msg_id, "status": "ok", "result": result}
    except NotImplementedError:
        return {"id": msg_id, "status": "error", "error": f"{msg_type} not yet implemented"}
    except Exception as exc:
        log.exception("handler %s raised", msg_type)
        return {"id": msg_id, "status": "error", "error": str(exc)}


def main() -> None:
    log.info("worker started (pid=%d)", __import__("os").getpid())
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            log.warning("malformed NDJSON: %s", exc)
            continue
        response = _dispatch(msg)
        print(json.dumps(response), flush=True)


if __name__ == "__main__":
    main()
