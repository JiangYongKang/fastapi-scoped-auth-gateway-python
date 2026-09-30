"""Structured audit log.

Every request produces an audit record describing the presented input and
the reason for the final decision. This is what makes the chain
"explainable": tests assert on these records.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

logger = logging.getLogger("auth_gateway.audit")


@dataclass
class AuditRecord:
    event: str
    credential_kind: str | None = None
    credential_id: str | None = None
    required_scope: str | None = None
    granted_scopes: list[str] = field(default_factory=list)
    decision: str = "deny"
    reason: str | None = None
    legacy: bool = False
    migration_marker: str | None = None
    rate_limit_remaining: int | None = None
    detail: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class Auditor:
    """Collects audit records in memory and logs them."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._lock = Lock()

    def record(self, entry: AuditRecord) -> None:
        with self._lock:
            self._records.append(entry)
        # Single-line JSON so test logs show inputs and decision basis.
        payload = {
            "event": entry.event,
            "credential_kind": entry.credential_kind,
            "credential_id": entry.credential_id,
            "required_scope": entry.required_scope,
            "granted_scopes": entry.granted_scopes,
            "decision": entry.decision,
            "reason": entry.reason,
            "legacy": entry.legacy,
            "migration_marker": entry.migration_marker,
            "rate_limit_remaining": entry.rate_limit_remaining,
            "detail": entry.detail,
            **{f"extra.{k}": v for k, v in entry.extra.items()},
        }
        logger.info(
            "audit %s",
            json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str),
        )

    def all(self) -> list[AuditRecord]:
        with self._lock:
            return list(self._records)

    def records_for(self, credential_id: str) -> list[AuditRecord]:
        with self._lock:
            return [
                r for r in self._records if r.credential_id == credential_id
            ]

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
