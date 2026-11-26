"""Server-side authentication, session token binding, and deterministic policy engine (R01-R10)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from fastapi import HTTPException, Request, status

from config import (
    CLEARANCE_LEVELS,
    HARNESS_ALLOWED_TOOLS,
    MAX_DOCS_PER_CALL,
    MAX_DOCS_PER_SESSION,
    MAX_UNAUTHORIZED_ATTEMPTS_PER_SESSION,
    MIN_ANONYMITY_GROUP_SIZE,
    settings,
)
from models import DemoAccountInfo, UserProfile


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    username: str
    display_name: str
    title: str
    role: str
    department: str
    clearance: str
    password_salt: str
    password_hash: str

    def to_profile(self) -> UserProfile:
        return UserProfile(
            user_id=self.user_id,
            username=self.username,
            display_name=self.display_name,
            title=self.title,
            role=self.role,
            department=self.department,
            clearance=self.clearance,  # type: ignore[arg-type]
        )


def _hash_password(password: str, salt: str) -> str:
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120_000)
    return base64.b64encode(dk).decode("ascii")


def _build_synthetic_directory() -> Dict[str, UserRecord]:
    """Create the synthetic enterprise identity directory on the server."""
    specs = [
        {
            "user_id": "usr-claire-vance",
            "username": "claire.vance",
            "display_name": "Claire Vance",
            "title": "Senior Financial Analyst",
            "role": "analyst",
            "department": "finance",
            "clearance": "internal",
            "password": "Redacted-Analyst-2026!",
            "salt": "nbh-salt-01",
        },
        {
            "user_id": "usr-marcus-chen",
            "username": "marcus.chen",
            "display_name": "Marcus Chen",
            "title": "Operations Specialist",
            "role": "operations",
            "department": "operations",
            "clearance": "internal",
            "password": "Redacted-Ops-2026!",
            "salt": "nbh-salt-02",
        },
        {
            "user_id": "usr-david-okafor",
            "username": "david.okafor",
            "display_name": "David Okafor",
            "title": "General Counsel",
            "role": "legal",
            "department": "legal",
            "clearance": "confidential",
            "password": "Redacted-Legal-2026!",
            "salt": "nbh-salt-03",
        },
        {
            "user_id": "usr-helena-park",
            "username": "helena.park",
            "display_name": "Helena Park",
            "title": "Compliance Auditor",
            "role": "compliance",
            "department": "compliance",
            "clearance": "internal",
            "password": "Redacted-Audit-2026!",
            "salt": "nbh-salt-04",
        },
    ]
    directory: Dict[str, UserRecord] = {}
    for item in specs:
        directory[item["username"]] = UserRecord(
            user_id=item["user_id"],
            username=item["username"],
            display_name=item["display_name"],
            title=item["title"],
            role=item["role"],
            department=item["department"],
            clearance=item["clearance"],
            password_salt=item["salt"],
            password_hash=_hash_password(item["password"], item["salt"]),
        )
    return directory


USER_DIRECTORY: Dict[str, UserRecord] = _build_synthetic_directory()
USERS_BY_ID: Dict[str, UserRecord] = {u.user_id: u for u in USER_DIRECTORY.values()}


def list_demo_accounts() -> List[DemoAccountInfo]:
    return [
        DemoAccountInfo(
            username=u.username,
            display_name=u.display_name,
            title=u.title,
            role=u.role,
            department=u.department,
            clearance=u.clearance,
        )
        for u in USER_DIRECTORY.values()
    ]


def authenticate_credentials(username: str, password: str) -> Optional[UserRecord]:
    user = USER_DIRECTORY.get(username.strip().lower())
    if user is None:
        return None
    candidate = _hash_password(password, user.password_salt)
    if not hmac.compare_digest(candidate, user.password_hash):
        return None
    return user


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(val: str) -> bytes:
    padding = "=" * (-len(val) % 4)
    return base64.urlsafe_b64decode(val + padding)


def create_access_token(user: UserRecord, ttl_hours: int = 8) -> tuple[str, str]:
    """Sign a server-verifiable HMAC-SHA256 bearer token bound strictly to server directory."""
    now = datetime.now(timezone.utc)
    exp = now + timedelta(hours=ttl_hours)
    header = _b64url_encode(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload_dict = {
        "sub": user.user_id,
        "username": user.username,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": secrets.token_hex(8),
    }
    payload = _b64url_encode(json.dumps(payload_dict, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = hmac.new(settings.redacted_auth_secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    token = f"{header}.{payload}.{_b64url_encode(sig)}"
    return token, exp.isoformat()


def verify_access_token(token: str) -> Optional[UserRecord]:
    """Verify token signature, expiration, and resolve authoritative server UserRecord."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        expected_sig = hmac.new(
            settings.redacted_auth_secret.encode("utf-8"), signing_input, hashlib.sha256
        ).digest()
        provided_sig = _b64url_decode(sig_b64)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return None
        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(datetime.now(timezone.utc).timestamp()):
            return None
        user_id = payload.get("sub")
        if not isinstance(user_id, str):
            return None
        return USERS_BY_ID.get(user_id)
    except Exception:
        return None


def get_current_user(request: Request) -> UserRecord:
    """FastAPI dependency enforcing R09: deny when authorization cannot be established."""
    from audit import audit_logger

    auth_header = request.headers.get("Authorization", "")
    request_id = getattr(request.state, "request_id", "req-unauth")
    if not auth_header.startswith("Bearer "):
        audit_logger.log_event(
            request_id=request_id,
            user_id="anonymous",
            user_role="unauthenticated",
            operation=f"{request.method} {request.url.path}",
            access_decision="DENY",
            triggered_rule="R09",
            reason="Authorization could not be established: missing Bearer token.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"rule": "R09", "message": "Authorization cannot be established. Sign in required."},
        )

    token = auth_header[len("Bearer ") :].strip()
    user = verify_access_token(token)
    if user is None:
        audit_logger.log_event(
            request_id=request_id,
            user_id="unknown",
            user_role="unverified",
            operation=f"{request.method} {request.url.path}",
            access_decision="DENY",
            triggered_rule="R09",
            reason="Authorization could not be established: invalid or expired session token.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"rule": "R09", "message": "Invalid or expired session token."},
        )
    return user


@dataclass
class SessionSecurityState:
    """Tracks per-session retrieval counts and unauthorized probing (R04, R08)."""

    session_id: str
    user_id: str
    retrieved_doc_ids: List[str] = field(default_factory=list)
    unauthorized_attempts: int = 0
    locked_for_exfiltration: bool = False
    audit_probes: int = 0


@dataclass
class PolicyDecision:
    allowed: bool
    rule_id: str
    reason: str
    triggered_rules: List[str] = field(default_factory=list)


_PATTERNS_R02_MUTATION = re.compile(
    r"\b(?:delete|remove|erase|drop|modify|edit|overwrite|update|truncate|wipe|corrupt)\b.*\b(?:report|record|document|file|handbook|contract|payroll|data|s3)\b",
    re.IGNORECASE,
)
_PATTERNS_R03_PII_OR_ENCODING = re.compile(
    r"(?:\b(?:payroll|salary|salaries|compensation|ssn|social\s+security|tax\s+id|routing\s+number|bank\s+account)\b.*\b(?:ceo|cfo|executive|employee|reveal|show|base64|hex|rot13|encode|decode)\b|\b(?:ceo(?:'s)?|cfo(?:'s)?)\s+(?:salary|compensation|pay|bonus)\b|\breveal\s+payroll\b|\bbase64\b.*\b(?:salary|payroll|ceo)\b)",
    re.IGNORECASE,
)
_PATTERNS_R04_BULK_EXPORT = re.compile(
    r"\b(?:export\s+all|dump\s+all|download\s+all|list\s+and\s+dump|exfiltrate|entire\s+database|all\s+confidential\s+records|all\s+restricted\s+records|all\s+company\s+records)\b",
    re.IGNORECASE,
)
_PATTERNS_R06_IDENTITY_CLAIM = re.compile(
    r"(?:\bi\s+am\s+(?:the\s+)?(?:admin|administrator|ceo|cfo|root|superuser|general\s+counsel|security\s+officer)\b|\bgrant\s+me\s+(?:full|admin|elevated|unrestricted)\s+access\b|\bpretend(?:ing)?\s+(?:this\s+is|to\s+be)\s+(?:a\s+)?(?:security\s+)?audit\b|\burgent\s+(?:external\s+)?security\s+audit\b.*\breveal\b|\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b)",
    re.IGNORECASE,
)
_PATTERNS_R07_FABRICATION = re.compile(
    r"(?:\b(?:invent|fabricate|make\s+up|guess|estimate\s+without\s+data|hallucinate)\b.*\b(?:revenue|figure|numbers|q4|2026|2027|projection|data)\b)",
    re.IGNORECASE,
)
_PATTERNS_R08_SMALL_GROUP = re.compile(
    r"(?:\b(?:average|mean|median|total|sum)\s+(?:salary|compensation|pay)\b.*\b(?:one\s+employee|single\s+employee|only\s+one|1\s+employee|corporate\s+strategy|fewer\s+than\s+5)\b|\bcorporate\s+strategy\b.*\b(?:salary|compensation|pay)\b)",
    re.IGNORECASE,
)
_PATTERNS_R04_INCREMENTAL_PROBE = re.compile(
    r"(?:\bfirst\s+(?:paragraph|row|rows|line|lines)\s+of\b|\bonly\s+the\s+(?:ceo\s+row|first\s+field|one\s+field)\b|\bone\s+at\s+a\s+time\b)",
    re.IGNORECASE,
)


class PolicyEngine:
    """Deterministic authorization-before-retrieval policy engine enforcing R01-R10."""

    def __init__(self) -> None:
        self._sessions: Dict[str, SessionSecurityState] = {}

    def get_or_create_session_state(self, session_id: str, user_id: str) -> SessionSecurityState:
        state = self._sessions.get(session_id)
        if state is None:
            state = SessionSecurityState(session_id=session_id, user_id=user_id)
            self._sessions[session_id] = state
        elif state.user_id != user_id:
            raise PermissionError("R09: Session identity mismatch; cross-user session reuse denied.")
        return state

    def evaluate_user_prompt(
        self,
        user: UserRecord,
        prompt: str,
        session_state: SessionSecurityState,
    ) -> PolicyDecision:
        """Classify deterministic prompt-level policy violations before or alongside Harness run."""
        if session_state.locked_for_exfiltration:
            return PolicyDecision(
                allowed=False,
                rule_id="R04",
                triggered_rules=["R04", "R03"],
                reason="Session locked after repeated unauthorized or incremental extraction attempts.",
            )

        triggered: List[str] = []
        reasons: List[str] = []

        if _PATTERNS_R02_MUTATION.search(prompt):
            triggered.append("R02")
            reasons.append("Company records are strictly read-only; modification or deletion is prohibited.")

        if _PATTERNS_R06_IDENTITY_CLAIM.search(prompt):
            triggered.append("R06")
            reasons.append("Conversational role, admin, or audit authority claims are ignored; server identity governs access.")

        if _PATTERNS_R04_BULK_EXPORT.search(prompt):
            triggered.append("R04")
            reasons.append("Unauthorized bulk export or full-corpus extraction is prohibited.")

        if _PATTERNS_R08_SMALL_GROUP.search(prompt):
            triggered.append("R08")
            reasons.append(
                f"Department compensation statistics require at least {MIN_ANONYMITY_GROUP_SIZE} employees to prevent individual salary inference."
            )

        if _PATTERNS_R03_PII_OR_ENCODING.search(prompt):
            triggered.append("R03")
            reasons.append("Disclosure of restricted payroll, personal tax IDs, or individual executive compensation (including encoded forms) is prohibited.")

        if _PATTERNS_R07_FABRICATION.search(prompt):
            triggered.append("R07")
            reasons.append("Missing figures cannot be invented or extrapolated when absent from authorized records.")

        if _PATTERNS_R04_INCREMENTAL_PROBE.search(prompt) and any(
            k in prompt.lower()
            for k in ("confidential", "payroll", "exec", "doc-contracts", "doc-payroll", "doc-exec")
        ):
            session_state.audit_probes += 1
            if "R04" not in triggered:
                triggered.append("R04")
            reasons.append("Incremental partial extraction of restricted/confidential records is blocked.")

        if triggered:
            session_state.unauthorized_attempts += 1
            if session_state.unauthorized_attempts >= MAX_UNAUTHORIZED_ATTEMPTS_PER_SESSION:
                session_state.locked_for_exfiltration = True
            return PolicyDecision(
                allowed=False,
                rule_id=triggered[0],
                triggered_rules=triggered,
                reason=" ".join(reasons),
            )

        return PolicyDecision(
            allowed=True,
            rule_id="NONE",
            triggered_rules=[],
            reason="Prompt passed deterministic pre-invocation checks; proceeding to AgentCore Managed Harness.",
        )

    def authorize_document_access(self, user: Optional[UserRecord], doc_meta: Dict[str, Any]) -> PolicyDecision:
        """Authorization BEFORE retrieval (R01, R03, R09)."""
        if user is None:
            return PolicyDecision(
                allowed=False,
                rule_id="R09",
                triggered_rules=["R09"],
                reason="Authorization cannot be established without a verified user session.",
            )

        doc_id = str(doc_meta.get("doc_id", "unknown"))
        access_level = str(doc_meta.get("access_level", "restricted"))
        user_rank = CLEARANCE_LEVELS.get(user.clearance, -1)
        doc_rank = CLEARANCE_LEVELS.get(access_level, 99)

        if user_rank < 0 or doc_rank > 3:
            return PolicyDecision(
                allowed=False,
                rule_id="R09",
                triggered_rules=["R09"],
                reason=f"Indeterminate clearance or document classification for {doc_id}; failing closed.",
            )

        if access_level == "restricted" or doc_meta.get("pii_protected"):
            return PolicyDecision(
                allowed=False,
                rule_id="R03",
                triggered_rules=["R03", "R01"],
                reason=f"Access to restricted personal/executive record {doc_id} is denied under R03 and R01.",
            )

        if user_rank < doc_rank:
            return PolicyDecision(
                allowed=False,
                rule_id="R01",
                triggered_rules=["R01"],
                reason=f"Role '{user.role}' (clearance '{user.clearance}') is not permitted to access '{access_level}' document {doc_id}.",
            )

        allowed_roles: Set[str] = set(doc_meta.get("allowed_roles", []))
        if allowed_roles and user.role not in allowed_roles:
            return PolicyDecision(
                allowed=False,
                rule_id="R01",
                triggered_rules=["R01"],
                reason=f"Role '{user.role}' is outside the authorized role list for {doc_id}.",
            )

        allowed_depts: Set[str] = set(doc_meta.get("allowed_departments", []))
        if allowed_depts and "all" not in allowed_depts and user.department not in allowed_depts:
            return PolicyDecision(
                allowed=False,
                rule_id="R01",
                triggered_rules=["R01"],
                reason=f"Department '{user.department}' is not authorized to access {doc_id}.",
            )

        return PolicyDecision(
            allowed=True,
            rule_id="NONE",
            triggered_rules=[],
            reason=f"Authorized read access to {doc_id} ({access_level}) for {user.username}.",
        )

    def authorize_tool_call(
        self,
        user: UserRecord,
        session_state: SessionSecurityState,
        tool_name: str,
        tool_args: Dict[str, Any],
        manifest_docs: Dict[str, Dict[str, Any]],
        department_headcounts: Dict[str, int],
    ) -> PolicyDecision:
        """Deterministic pre-retrieval authorization for AgentCore Harness tool calls."""
        if session_state.locked_for_exfiltration:
            return PolicyDecision(
                allowed=False,
                rule_id="R04",
                triggered_rules=["R04"],
                reason="Session locked after repeated unauthorized extraction attempts.",
            )

        allowed_plain_names = {t.lstrip("@") for t in HARNESS_ALLOWED_TOOLS}
        if tool_name not in allowed_plain_names:
            session_state.unauthorized_attempts += 1
            return PolicyDecision(
                allowed=False,
                rule_id="R02",
                triggered_rules=["R02", "R09"],
                reason=f"Tool '{tool_name}' is not in the read-only policy allowlist.",
            )

        if tool_name == "list_authorized_documents":
            return PolicyDecision(
                allowed=True,
                rule_id="NONE",
                triggered_rules=[],
                reason="Listing authorized document metadata filtered by caller clearance.",
            )

        if tool_name == "search_authorized_documents":
            limit = int(tool_args.get("limit", 3) or 3)
            if limit > MAX_DOCS_PER_CALL:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R04",
                    triggered_rules=["R04"],
                    reason=f"Requested result limit {limit} exceeds maximum per-call cap ({MAX_DOCS_PER_CALL}).",
                )
            query_text = str(tool_args.get("query", ""))
            if _PATTERNS_R03_PII_OR_ENCODING.search(query_text) or _PATTERNS_R04_BULK_EXPORT.search(query_text):
                session_state.unauthorized_attempts += 1
                return PolicyDecision(
                    allowed=False,
                    rule_id="R03",
                    triggered_rules=["R03"],
                    reason="Search query targets restricted payroll/compensation or bulk extraction.",
                )
            return PolicyDecision(
                allowed=True,
                rule_id="NONE",
                triggered_rules=[],
                reason="Authorized search across permitted documents only.",
            )

        if tool_name == "get_authorized_document":
            doc_id = str(tool_args.get("doc_id", "")).strip()
            if not doc_id or doc_id not in manifest_docs:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R09",
                    triggered_rules=["R09"],
                    reason=f"Unknown or missing document ID '{doc_id}'; failing closed.",
                )

            if len(session_state.retrieved_doc_ids) >= MAX_DOCS_PER_SESSION and doc_id not in session_state.retrieved_doc_ids:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R04",
                    triggered_rules=["R04"],
                    reason=f"Cumulative session retrieval limit ({MAX_DOCS_PER_SESSION}) reached to prevent incremental exfiltration.",
                )

            decision = self.authorize_document_access(user, manifest_docs[doc_id])
            if not decision.allowed:
                session_state.unauthorized_attempts += 1
                if session_state.unauthorized_attempts >= MAX_UNAUTHORIZED_ATTEMPTS_PER_SESSION:
                    session_state.locked_for_exfiltration = True
                return decision

            if doc_id not in session_state.retrieved_doc_ids:
                session_state.retrieved_doc_ids.append(doc_id)
            return decision

        if tool_name == "get_department_compensation_summary":
            dept = str(tool_args.get("department", "")).strip()
            if not dept:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R09",
                    triggered_rules=["R09"],
                    reason="Department name is required; failing closed.",
                )

            matched_key = next((k for k in department_headcounts if k.lower() == dept.lower()), None)
            if matched_key is None:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R09",
                    triggered_rules=["R09"],
                    reason=f"Department '{dept}' not found in authorized roster.",
                )

            headcount = department_headcounts[matched_key]
            if headcount < MIN_ANONYMITY_GROUP_SIZE:
                session_state.unauthorized_attempts += 1
                return PolicyDecision(
                    allowed=False,
                    rule_id="R08",
                    triggered_rules=["R08"],
                    reason=(
                        f"Indirect salary disclosure prevented: '{matched_key}' has {headcount} employee(s), "
                        f"below the minimum anonymity cohort threshold of {MIN_ANONYMITY_GROUP_SIZE}."
                    ),
                )

            if CLEARANCE_LEVELS.get(user.clearance, 0) < CLEARANCE_LEVELS["internal"] or user.role not in {"analyst", "legal", "compliance"}:
                return PolicyDecision(
                    allowed=False,
                    rule_id="R01",
                    triggered_rules=["R01"],
                    reason=f"Role '{user.role}' lacks authorization for departmental compensation band summaries.",
                )

            return PolicyDecision(
                allowed=True,
                rule_id="NONE",
                triggered_rules=[],
                reason=f"Authorized k-anonymous aggregate band for '{matched_key}' (n={headcount} >= {MIN_ANONYMITY_GROUP_SIZE}).",
            )

        return PolicyDecision(
            allowed=False,
            rule_id="R09",
            triggered_rules=["R09"],
            reason="Unhandled tool path denied by default.",
        )


policy_engine = PolicyEngine()
