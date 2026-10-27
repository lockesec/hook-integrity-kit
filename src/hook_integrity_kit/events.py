"""Findings as events: one JSON object per line, for a SIEM or a log shipper.

`verify --format jsonl` and `audit --format jsonl` write one event per finding and always one
`RUN` event, so a run that found nothing is a positive "checked, clean" record and a run that
could not look is an event with `evaluable: false`, never silence. `session-start --events FILE`
appends the same events to a local file for a shipper (Filebeat, Vector, rsyslog) to collect;
the kit itself never sends anything over the network.

The schema is versioned (`schema`); fields are documented in docs/events.md. ATT&CK ids are
Enterprise ATT&CK v20 ids, read in MITRE's STIX data; each is the technique MITRE uses for the
same behaviour where it has one (S9043 Mini Shai-Hulud: T1546, T1554).
"""
from __future__ import annotations

import datetime
import json
import socket
from pathlib import Path
from typing import Iterable, List, Optional

SCHEMA = "hook-integrity-kit.finding/1"

#: verify field -> (kind, severity, evaluable, ATT&CK ids)
VERIFY_KINDS = {
    "modified": ("MODIFIED", "high", True, ["T1546", "T1554"]),
    "added": ("ADDED", "high", True, ["T1546"]),
    "removed": ("REMOVED", "medium", True, []),
    "settings_changed": ("SETTINGS", "high", True, ["T1546"]),
    "escalated": ("ESCALATED", "high", True, ["T1685"]),
    "bytecode_changed": ("BYTECODE", "high", True, ["T1554"]),
    "kit_changed": ("KIT_CHANGED", "high", True, ["T1685"]),
    "global_changes": ("GLOBAL", "medium", True, ["T1546"]),
    "info_new_unregistered": ("UNREGISTERED", "info", True, []),
    "external_unchecked": ("NOT_CHECKED", "info", False, []),
    "not_checked": ("NOT_CHECKED", "info", False, []),
}


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _base(source: str, project: Optional[str], when: str) -> dict:
    return {"schema": SCHEMA, "event_time": when, "host": socket.gethostname(),
            "project": project, "source": source}


def from_verify(findings: dict, project: Optional[str], source: str = "verify") -> List[dict]:
    """Events for a `verify` (or session-start) result dict."""
    when = _now()
    status = findings.get("status")
    out: List[dict] = []
    counts = {}
    for key, (kind, sev, evaluable, attack) in VERIFY_KINDS.items():
        for item in findings.get(key, []) or []:
            out.append({**_base(source, project, when), "kind": kind, "severity": sev,
                        "evaluable": evaluable, "detail": str(item), "attack": attack})
            counts[kind] = counts.get(kind, 0) + 1
    run = {**_base(source, project, when), "kind": "RUN", "status": status,
           "severity": {"drift": "high", "clean": "info"}.get(status, "medium"),
           "evaluable": status in ("clean", "drift"), "counts": counts, "attack": []}
    if status not in ("clean", "drift"):
        run["detail"] = findings.get("error") or ("no baseline yet" if status == "no-baseline"
                                                  else str(status))
    if findings.get("global_status") is not None:
        run["global_status"] = findings.get("global_status")
    return out + [run]


def from_audit(items: Iterable, unreadable: Iterable, project: Optional[str]) -> List[dict]:
    """Events for an `audit`: one AUTO_RUN per item (high when flagged, medium with a review
    note, info otherwise), one NOT_EVALUABLE per unreadable config, and a RUN event."""
    when = _now()
    out: List[dict] = []
    flagged = 0
    for kind, where, what, flags, notes in items:
        sev = "high" if flags else "medium" if notes else "info"
        flagged += bool(flags)
        out.append({**_base("audit", project, when), "kind": "AUTO_RUN", "severity": sev,
                    "evaluable": True, "detail": what, "path": where, "registration": kind,
                    "flags": list(flags), "notes": list(notes), "attack": ["T1546"]})
    unread = list(unreadable)
    for u in unread:
        out.append({**_base("audit", project, when), "kind": "NOT_EVALUABLE", "severity": "medium",
                    "evaluable": False, "detail": u, "attack": []})
    status = "error" if unread else "flagged" if flagged else "listed"
    out.append({**_base("audit", project, when), "kind": "RUN", "status": status,
                "severity": "high" if flagged else "medium" if unread else "info",
                "evaluable": not unread, "attack": [],
                "counts": {"AUTO_RUN": len(out) - len(unread), "flagged": flagged,
                           "NOT_EVALUABLE": len(unread)}})
    return out


def dumps(events: List[dict]) -> str:
    return "\n".join(json.dumps(e, sort_keys=True) for e in events)


def append(path: Path, events: List[dict]) -> None:
    """Append events to a JSONL file (created if missing). Raises OSError to the caller."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(dumps(events) + "\n")
