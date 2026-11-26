"""Read-only document store enforcing authorization before S3, Lambda, or local retrieval (R01, R02, R08, R09)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, ProfileNotFound

from audit import audit_logger
from authorization import PolicyDecision, SessionSecurityState, UserRecord, policy_engine
from config import DATA_DIR, MIN_ANONYMITY_GROUP_SIZE, get_boto_session, settings
from guardrails import SanitizedDocument, sanitize_untrusted_document
from models import RecordSummary


class DocumentStore:
    """Server-side read-only repository over S3 / Lambda Retriever / local synthetic JSON."""

    def __init__(self, data_dir: Optional[Path] = None) -> None:
        self._data_dir = data_dir or DATA_DIR
        self._manifest = self._load_manifest()

    def _load_manifest(self) -> Dict[str, Any]:
        manifest_path = self._data_dir / "manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as fh:
            return json.load(fh)

    @property
    def organization_name(self) -> str:
        return str(self._manifest.get("organization", "Northbridge Holdings Group"))

    def manifest_by_id(self) -> Dict[str, Dict[str, Any]]:
        return {doc["doc_id"]: doc for doc in self._manifest.get("documents", [])}

    def _read_raw_document_object(self, meta: Dict[str, Any]) -> Tuple[Dict[str, Any], str]:
        """Fetch raw document payload AFTER authorization succeeded. Strictly read-only."""
        doc_id = meta["doc_id"]
        s3_key = meta["s3_key"]
        mode = settings.document_source_mode.lower()

        if settings.lambda_retriever_arn and mode in {"lambda", "auto"}:
            try:
                lam = get_boto_session().client("lambda", region_name=settings.aws_region)
                resp = lam.invoke(
                    FunctionName=settings.lambda_retriever_arn,
                    InvocationType="RequestResponse",
                    Payload=json.dumps({"bucket": settings.s3_documents_bucket, "key": s3_key, "doc_id": doc_id}).encode("utf-8"),
                )
                payload = json.loads(resp["Payload"].read().decode("utf-8"))
                if payload.get("statusCode") == 200 and "document" in payload:
                    return payload["document"], f"lambda:{settings.lambda_retriever_arn}"
            except (NoCredentialsError, ProfileNotFound, ClientError, BotoCoreError):
                if mode == "lambda":
                    raise

        if settings.s3_documents_bucket and mode in {"s3", "auto"}:
            try:
                s3 = get_boto_session().client("s3", region_name=settings.aws_region)
                obj = s3.get_object(Bucket=settings.s3_documents_bucket, Key=s3_key)
                data = json.loads(obj["Body"].read().decode("utf-8"))
                return data, f"s3://{settings.s3_documents_bucket}/{s3_key}"
            except (NoCredentialsError, ProfileNotFound, ClientError, BotoCoreError):
                if mode == "s3":
                    raise

        local_path = self._data_dir / f"{doc_id}.json"
        with open(local_path, "r", encoding="utf-8") as fh:
            return json.load(fh), f"local:{doc_id}.json"

    def list_records_for_user(self, user: UserRecord, request_id: str) -> List[RecordSummary]:
        """Return all categories with restricted contents withheld server-side (R01, R03)."""
        summaries: List[RecordSummary] = []
        for meta in self._manifest.get("documents", []):
            decision = policy_engine.authorize_document_access(user, meta)
            if decision.allowed:
                raw, _ = self._read_raw_document_object(meta)
                summaries.append(
                    RecordSummary(
                        doc_id=meta["doc_id"],
                        title=meta["title"],
                        category=meta["category"],
                        access_level=meta["access_level"],
                        owner=meta["owner"],
                        last_updated=meta["last_updated"],
                        accessible=True,
                        redacted=False,
                        summary=str(raw.get("summary", "")),
                        content=str(raw.get("content", "")),
                    )
                )
            else:
                summaries.append(
                    RecordSummary(
                        doc_id=meta["doc_id"],
                        title=meta["title"],
                        category=meta["category"],
                        access_level=meta["access_level"],
                        owner=meta["owner"],
                        last_updated=meta["last_updated"],
                        accessible=False,
                        redacted=True,
                        summary="[REDACTED — SERVER CLEARANCE REQUIRED]",
                        content=None,
                        denial_rule=decision.rule_id,
                        denial_reason=decision.reason,
                    )
                )

        audit_logger.log_event(
            request_id=request_id,
            user_id=user.user_id,
            user_role=user.role,
            operation="LIST_RECORDS",
            access_decision="ALLOW",
            triggered_rule="R01",
            reason=f"Returned {sum(1 for s in summaries if s.accessible)} authorized and {sum(1 for s in summaries if not s.accessible)} redacted record entries.",
        )
        return summaries

    def get_record_for_user(
        self,
        user: UserRecord,
        doc_id: str,
        request_id: str,
        *,
        session_state: Optional[SessionSecurityState] = None,
        sanitize_for_agent: bool = False,
    ) -> Tuple[PolicyDecision, Optional[Dict[str, Any]], Optional[SanitizedDocument], str]:
        """Check policy BEFORE retrieval; read only if authorized."""
        manifest_map = self.manifest_by_id()
        meta = manifest_map.get(doc_id)
        if meta is None:
            decision = PolicyDecision(
                allowed=False,
                rule_id="R09",
                triggered_rules=["R09"],
                reason=f"Record '{doc_id}' does not exist; access denied.",
            )
            audit_logger.log_event(
                request_id=request_id,
                user_id=user.user_id,
                user_role=user.role,
                operation="GET_RECORD",
                access_decision="DENY",
                triggered_rule="R09",
                reason=decision.reason,
                doc_id=doc_id,
            )
            return decision, None, None, "none"

        if session_state is not None:
            decision = policy_engine.authorize_tool_call(
                user=user,
                session_state=session_state,
                tool_name="get_authorized_document",
                tool_args={"doc_id": doc_id},
                manifest_docs=manifest_map,
                department_headcounts=self.get_department_headcounts(),
            )
        else:
            decision = policy_engine.authorize_document_access(user, meta)

        if not decision.allowed:
            audit_logger.log_event(
                request_id=request_id,
                user_id=user.user_id,
                user_role=user.role,
                operation="GET_RECORD",
                access_decision="DENY",
                triggered_rule=decision.rule_id,
                reason=decision.reason,
                doc_id=doc_id,
            )
            return decision, None, None, "blocked-before-retrieval"

        raw, source = self._read_raw_document_object(meta)
        sanitized_doc: Optional[SanitizedDocument] = None
        if sanitize_for_agent:
            sanitized_doc = sanitize_untrusted_document(
                doc_id=doc_id,
                title=meta["title"],
                access_level=meta["access_level"],
                raw_content=str(raw.get("content", "")),
            )
            if sanitized_doc.injection_detected:
                audit_logger.log_event(
                    request_id=request_id,
                    user_id=user.user_id,
                    user_role=user.role,
                    operation="DOCUMENT_SANITIZE",
                    access_decision="BLOCKED",
                    triggered_rule="R05",
                    reason=f"Neutralized embedded untrusted instruction directive(s) inside {doc_id}: {', '.join(sanitized_doc.findings)}.",
                    doc_id=doc_id,
                )

        audit_logger.log_event(
            request_id=request_id,
            user_id=user.user_id,
            user_role=user.role,
            operation="GET_RECORD",
            access_decision="ALLOW",
            triggered_rule="R01",
            reason=f"Authorized read of {doc_id} from {source}.",
            doc_id=doc_id,
        )
        return decision, raw, sanitized_doc, source

    def search_authorized_documents(
        self,
        user: UserRecord,
        query: str,
        limit: int,
        request_id: str,
        session_state: SessionSecurityState,
    ) -> Tuple[PolicyDecision, List[Dict[str, Any]]]:
        """Search ONLY documents the user is permitted to read (R01, R04, R05)."""
        manifest_map = self.manifest_by_id()
        decision = policy_engine.authorize_tool_call(
            user=user,
            session_state=session_state,
            tool_name="search_authorized_documents",
            tool_args={"query": query, "limit": limit},
            manifest_docs=manifest_map,
            department_headcounts=self.get_department_headcounts(),
        )
        if not decision.allowed:
            audit_logger.log_event(
                request_id=request_id,
                user_id=user.user_id,
                user_role=user.role,
                operation="SEARCH_RECORDS",
                access_decision="DENY",
                triggered_rule=decision.rule_id,
                reason=decision.reason,
                tool_name="search_authorized_documents",
            )
            return decision, []

        terms = [t.lower() for t in query.split() if len(t) > 2]
        matches: List[Dict[str, Any]] = []
        for doc_id, meta in manifest_map.items():
            doc_decision = policy_engine.authorize_document_access(user, meta)
            if not doc_decision.allowed:
                continue
            raw, source = self._read_raw_document_object(meta)
            haystack = f"{meta['title']} {meta['category']} {raw.get('summary', '')} {raw.get('content', '')}".lower()
            score = sum(1 for t in terms if t in haystack)
            if score > 0 or not terms:
                san = sanitize_untrusted_document(doc_id, meta["title"], meta["access_level"], str(raw.get("content", "")))
                if san.injection_detected:
                    audit_logger.log_event(
                        request_id=request_id,
                        user_id=user.user_id,
                        user_role=user.role,
                        operation="DOCUMENT_SANITIZE",
                        access_decision="BLOCKED",
                        triggered_rule="R05",
                        reason=f"Neutralized untrusted directive inside {doc_id} during search.",
                        doc_id=doc_id,
                    )
                matches.append(
                    {
                        "score": score,
                        "doc_id": doc_id,
                        "title": meta["title"],
                        "category": meta["category"],
                        "access_level": meta["access_level"],
                        "source": source,
                        "summary": raw.get("summary", ""),
                        "excerpt": san.wrapped_text[:900],
                    }
                )

        matches.sort(key=lambda m: m["score"], reverse=True)
        limited = matches[: max(1, min(limit, 3))]
        audit_logger.log_event(
            request_id=request_id,
            user_id=user.user_id,
            user_role=user.role,
            operation="SEARCH_RECORDS",
            access_decision="ALLOW",
            triggered_rule="R01",
            reason=f"Returned {len(limited)} authorized search result(s).",
            tool_name="search_authorized_documents",
        )
        return decision, limited

    def get_department_headcounts(self) -> Dict[str, int]:
        """Load non-sensitive department headcounts from authorized operations metadata."""
        q3_path = self._data_dir / "DOC-Q3-REV-2026.json"
        with open(q3_path, "r", encoding="utf-8") as fh:
            q3 = json.load(fh)
        return {d["name"]: int(d["headcount"]) for d in q3.get("departments", [])}

    def get_department_compensation_summary(
        self,
        user: UserRecord,
        department: str,
        request_id: str,
        session_state: SessionSecurityState,
    ) -> Tuple[PolicyDecision, Optional[Dict[str, Any]]]:
        """Enforce R08 k-anonymity (>= 5 employees) BEFORE releasing aggregate band."""
        headcounts = self.get_department_headcounts()
        decision = policy_engine.authorize_tool_call(
            user=user,
            session_state=session_state,
            tool_name="get_department_compensation_summary",
            tool_args={"department": department},
            manifest_docs=self.manifest_by_id(),
            department_headcounts=headcounts,
        )
        if not decision.allowed:
            audit_logger.log_event(
                request_id=request_id,
                user_id=user.user_id,
                user_role=user.role,
                operation="DEPT_COMP_SUMMARY",
                access_decision="DENY",
                triggered_rule=decision.rule_id,
                reason=decision.reason,
                tool_name="get_department_compensation_summary",
            )
            return decision, None

        q3_raw, source = self._read_raw_document_object(self.manifest_by_id()["DOC-Q3-REV-2026"])
        matched = next(
            (d for d in q3_raw.get("departments", []) if d["name"].lower() == department.strip().lower()),
            None,
        )
        if matched is None or int(matched.get("headcount", 0)) < MIN_ANONYMITY_GROUP_SIZE:
            deny = PolicyDecision(
                allowed=False,
                rule_id="R08",
                triggered_rules=["R08"],
                reason="Cohort size insufficient for k-anonymous aggregate reporting.",
            )
            audit_logger.log_event(
                request_id=request_id,
                user_id=user.user_id,
                user_role=user.role,
                operation="DEPT_COMP_SUMMARY",
                access_decision="DENY",
                triggered_rule="R08",
                reason=deny.reason,
                tool_name="get_department_compensation_summary",
            )
            return deny, None

        audit_logger.log_event(
            request_id=request_id,
            user_id=user.user_id,
            user_role=user.role,
            operation="DEPT_COMP_SUMMARY",
            access_decision="ALLOW",
            triggered_rule="R08",
            reason=f"Returned k-anonymous band for {matched['name']} (n={matched['headcount']}).",
            doc_id="DOC-Q3-REV-2026",
            tool_name="get_department_compensation_summary",
        )
        return decision, {
            "doc_id": "DOC-Q3-REV-2026",
            "title": "Q3 2026 Quarterly Revenue & Operations Report",
            "source": source,
            "department": matched["name"],
            "headcount": matched["headcount"],
            "aggregate_average_band_usd": matched["avg_salary_band_usd"],
            "k_anonymity_threshold": MIN_ANONYMITY_GROUP_SIZE,
        }


document_store = DocumentStore()
