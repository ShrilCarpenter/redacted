"""Sanitized security audit logger (R10) backed by SQLite and Amazon CloudWatch Logs."""

from __future__ import annotations

import json
import re
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from config import settings
from models import ActivityEvent

_SENSITIVE_SCRUB_PATTERNS = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED-TAX-ID]"),
    (re.compile(r"\b(?:SYN|SSN)[:\-]?\d{3,9}\b", re.IGNORECASE), "[REDACTED-ID]"),
    (re.compile(r"\$\s?\d{2,3},\d{3}(?:\.\d{2})?"), "[REDACTED-COMPENSATION]"),
    (re.compile(r"(?:base_salary|annual_bonus|salary|routing_last4)\s*[:=]\s*[^\s,;]+", re.IGNORECASE), "[REDACTED-FIELD]"),
    (re.compile(r"(?:[A-Za-z0-9+/]{32,}={0,2})"), "[REDACTED-ENCODED-PAYLOAD]"),
]


def scrub_sensitive_text(text: str, max_len: int = 400) -> str:
    """Remove PII, compensation numbers, or confidential payload fragments before logging (R10)."""
    cleaned = text or ""
    for pattern, replacement in _SENSITIVE_SCRUB_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    cleaned = " ".join(cleaned.split())
    if len(cleaned) > max_len:
        cleaned = cleaned[: max_len - 3] + "..."
    return cleaned


class AuditLogger:
    """Thread-safe security event recorder with optional CloudWatch Logs shipping."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._lock = threading.Lock()
        self._db_path = Path(db_path or settings.redacted_audit_db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._cw_sequence_token: Optional[str] = None
        self._init_db()

    def set_db_path(self, db_path: str) -> None:
        with self._lock:
            self._db_path = Path(db_path)
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    request_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    user_role TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    access_decision TEXT NOT NULL,
                    triggered_rule TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    doc_id TEXT,
                    tool_name TEXT,
                    aws_trace_id TEXT
                )
                """
            )
            conn.commit()

    def log_event(
        self,
        *,
        request_id: str,
        user_id: str,
        user_role: str,
        operation: str,
        access_decision: str,
        triggered_rule: str,
        reason: str,
        doc_id: Optional[str] = None,
        tool_name: Optional[str] = None,
        aws_trace_id: Optional[str] = None,
        emit_cloudwatch: bool = True,
    ) -> ActivityEvent:
        ts = datetime.now(timezone.utc).isoformat()
        safe_reason = scrub_sensitive_text(reason)
        safe_op = scrub_sensitive_text(operation, max_len=120)

        with self._lock:
            with self._connect() as conn:
                cur = conn.execute(
                    """
                    INSERT INTO security_events (
                        timestamp, request_id, user_id, user_role, operation,
                        access_decision, triggered_rule, reason, doc_id, tool_name, aws_trace_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ts,
                        request_id,
                        user_id,
                        user_role,
                        safe_op,
                        access_decision,
                        triggered_rule,
                        safe_reason,
                        doc_id,
                        tool_name,
                        aws_trace_id,
                    ),
                )
                row_id = int(cur.lastrowid or 0)
                conn.commit()

        event = ActivityEvent(
            id=row_id,
            timestamp=ts,
            request_id=request_id,
            user_id=user_id,
            user_role=user_role,
            operation=safe_op,
            access_decision=access_decision,  # type: ignore[arg-type]
            triggered_rule=triggered_rule,
            reason=safe_reason,
            doc_id=doc_id,
            tool_name=tool_name,
            aws_trace_id=aws_trace_id,
        )

        if emit_cloudwatch:
            self._ship_to_cloudwatch(event)

        return event

    def _ship_to_cloudwatch(self, event: ActivityEvent) -> None:
        """Best-effort shipping to Amazon CloudWatch Logs without sensitive content (R10)."""
        if not settings.cloudwatch_log_group:
            return
        try:
            client = boto3.client("logs", region_name=settings.aws_region)
            payload = {
                "timestamp": event.timestamp,
                "request_id": event.request_id,
                "user_id": event.user_id,
                "user_role": event.user_role,
                "operation": event.operation,
                "access_decision": event.access_decision,
                "triggered_rule": event.triggered_rule,
                "reason": event.reason,
                "doc_id": event.doc_id,
                "tool_name": event.tool_name,
                "aws_trace_id": event.aws_trace_id,
            }
            kwargs = {
                "logGroupName": settings.cloudwatch_log_group,
                "logStreamName": settings.cloudwatch_log_stream,
                "logEvents": [
                    {
                        "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
                        "message": json.dumps(payload, separators=(",", ":")),
                    }
                ],
            }
            if self._cw_sequence_token:
                kwargs["sequenceToken"] = self._cw_sequence_token
            resp = client.put_log_events(**kwargs)
            self._cw_sequence_token = resp.get("nextSequenceToken")
        except (NoCredentialsError, ClientError, BotoCoreError, Exception):
            return

    def list_events(self, limit: int = 150, decision: Optional[str] = None) -> tuple[List[ActivityEvent], int]:
        with self._lock:
            with self._connect() as conn:
                if decision:
                    total = conn.execute(
                        "SELECT COUNT(*) FROM security_events WHERE access_decision = ?", (decision,)
                    ).fetchone()[0]
                    rows = conn.execute(
                        "SELECT * FROM security_events WHERE access_decision = ? ORDER BY id DESC LIMIT ?",
                        (decision, limit),
                    ).fetchall()
                else:
                    total = conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0]
                    rows = conn.execute(
                        "SELECT * FROM security_events ORDER BY id DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
        events = [
            ActivityEvent(
                id=r["id"],
                timestamp=r["timestamp"],
                request_id=r["request_id"],
                user_id=r["user_id"],
                user_role=r["user_role"],
                operation=r["operation"],
                access_decision=r["access_decision"],
                triggered_rule=r["triggered_rule"],
                reason=r["reason"],
                doc_id=r["doc_id"],
                tool_name=r["tool_name"],
                aws_trace_id=r["aws_trace_id"],
            )
            for r in rows
        ]
        return events, int(total)


audit_logger = AuditLogger()
