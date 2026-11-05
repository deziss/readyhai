"""Machine-readable output of `main.py query --json` (stdlib only).

ReadyHai's agent calls the retriever as a subprocess and reads ONE JSON object from stdout. Everything in
it came from the indexed codebase, so it is untrusted text: it is redacted and bounded here, and the
caller treats it as data (report notes), never as instructions or test cases.

    {"evidence": [{"source": "app/search.py", "kind": "code", "summary": "..."}], "synthesis": "..." | null,
     "llm_error": "..." | null}
"""

import json
from typing import Any, Dict

from . import safety

MAX_EVIDENCE = 12
MAX_SUMMARY = 600
MAX_SYNTHESIS = 2000


def evidence_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    """The retrieval result as plain, redacted, size-bounded data."""
    evidence = []
    for blk in (result.get("evidence_blocks") or [])[:MAX_EVIDENCE]:
        evidence.append(
            {
                "source": safety.clean_label(str(blk.get("source", ""))),
                "kind": safety.clean_label(str(blk.get("kind", ""))),
                "summary": safety.redact(str(blk.get("summary", "")))[:MAX_SUMMARY],
            }
        )
    synthesis = result.get("final_synthesis")
    err = result.get("llm_error")
    return {
        "evidence": evidence,
        "synthesis": safety.redact(str(synthesis))[:MAX_SYNTHESIS] if synthesis else None,
        "llm_error": safety.redact(str(err))[:300] if err else None,
    }


def dumps(payload: Dict[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False)
