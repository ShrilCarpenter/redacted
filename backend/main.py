"""FastAPI entrypoint for Redacted."""

from __future__ import annotations

import sys
import uuid
from pathlib import Path
from typing import Optional

_BACKEND_DIR = str(Path(__file__).resolve().parent)
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from fastapi import Depends, FastAPI, HTTPException, Query, Request, status  # noqa: E402
from fastapi.middleware.cors import CORSMiddleware  # noqa: E402

from agent import BOUNDARY_TEST_CASES, agentcore_service, run_boundary_tests  # noqa: E402
from audit import audit_logger  # noqa: E402
from authorization import (  # noqa: E402
    UserRecord,
    authenticate_credentials,
    create_access_token,
    get_current_user,
    list_demo_accounts,
)
from config import settings  # noqa: E402
from documents import document_store  # noqa: E402
from models import (  # noqa: E402
    ActivityResponse,
    AwsStatusResponse,
    BoundaryTestCase,
    ChatMessageInput,
    ChatResponse,
    DemoAccountInfo,
    LoginRequest,
    LoginResponse,
    RecordsListResponse,
    RunTestsRequest,
    RunTestsResponse,
    UserProfile,
)

app = FastAPI(
    title="Redacted API",
    description="Enterprise workplace document assistant powered by Amazon Bedrock AgentCore Managed Harness.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def attach_request_id(request: Request, call_next):
    request.state.request_id = f"req-{uuid.uuid4().hex[:12]}"
    response = await call_next(request)
    response.headers["X-Request-Id"] = request.state.request_id
    return response


@app.get("/api/health")
def health_check() -> dict:
    return {"status": "ok", "service": "redacted-backend"}


@app.get("/api/aws/status", response_model=AwsStatusResponse)
def get_aws_status(_user: UserRecord = Depends(get_current_user)) -> AwsStatusResponse:
    return agentcore_service.check_aws_status()


@app.get("/api/auth/accounts", response_model=list[DemoAccountInfo])
def get_demo_accounts() -> list[DemoAccountInfo]:
    """Return synthetic enterprise directory personas (non-secret metadata only)."""
    return list_demo_accounts()


@app.post("/api/auth/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request) -> LoginResponse:
    req_id = getattr(request.state, "request_id", f"req-{uuid.uuid4().hex[:12]}")
    user = authenticate_credentials(body.username, body.password)
    if user is None:
        audit_logger.log_event(
            request_id=req_id,
            user_id=body.username[:40],
            user_role="unknown",
            operation="AUTH_LOGIN",
            access_decision="DENY",
            triggered_rule="R09",
            reason="Authentication failed: invalid username or password.",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"rule": "R09", "message": "Invalid credentials."},
        )

    token, exp = create_access_token(user)
    audit_logger.log_event(
        request_id=req_id,
        user_id=user.user_id,
        user_role=user.role,
        operation="AUTH_LOGIN",
        access_decision="ALLOW",
        triggered_rule="NONE",
        reason=f"Authenticated server session for {user.username} ({user.clearance}).",
    )
    return LoginResponse(access_token=token, expires_at=exp, user=user.to_profile())


@app.get("/api/auth/me", response_model=UserProfile)
def get_me(user: UserRecord = Depends(get_current_user)) -> UserProfile:
    return user.to_profile()


@app.get("/api/records", response_model=RecordsListResponse)
def list_records(request: Request, user: UserRecord = Depends(get_current_user)) -> RecordsListResponse:
    req_id = getattr(request.state, "request_id", f"req-{uuid.uuid4().hex[:12]}")
    records = document_store.list_records_for_user(user, req_id)
    return RecordsListResponse(
        organization=document_store.organization_name,
        user_clearance=user.clearance,
        records=records,
    )


@app.get("/api/records/{doc_id}")
def get_record(doc_id: str, request: Request, user: UserRecord = Depends(get_current_user)) -> dict:
    req_id = getattr(request.state, "request_id", f"req-{uuid.uuid4().hex[:12]}")
    decision, raw, _, source = document_store.get_record_for_user(
        user=user, doc_id=doc_id, request_id=req_id, sanitize_for_agent=False
    )
    if not decision.allowed or raw is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"rule": decision.rule_id, "message": decision.reason},
        )
    return {
        "doc_id": raw["doc_id"],
        "title": raw["title"],
        "category": raw["category"],
        "access_level": raw["access_level"],
        "effective_date": raw.get("effective_date"),
        "summary": raw.get("summary"),
        "content": raw.get("content"),
        "source": source,
    }


@app.post("/api/chat", response_model=ChatResponse)
def workspace_chat(
    body: ChatMessageInput,
    request: Request,
    user: UserRecord = Depends(get_current_user),
) -> ChatResponse:
    req_id = getattr(request.state, "request_id", f"req-{uuid.uuid4().hex[:12]}")
    return agentcore_service.ask_workspace(
        user=user,
        prompt=body.prompt,
        session_id=body.session_id,
        request_id=req_id,
    )


@app.get("/api/tests", response_model=list[BoundaryTestCase])
def list_boundary_tests(_user: UserRecord = Depends(get_current_user)) -> list[BoundaryTestCase]:
    return BOUNDARY_TEST_CASES


@app.post("/api/tests/run", response_model=RunTestsResponse)
def execute_boundary_tests(
    body: RunTestsRequest,
    user: UserRecord = Depends(get_current_user),
) -> RunTestsResponse:
    return run_boundary_tests(user=user, test_ids=body.test_ids)


@app.get("/api/activity", response_model=ActivityResponse)
def get_activity(
    limit: int = Query(default=150, ge=1, le=500),
    decision: Optional[str] = Query(default=None),
    _user: UserRecord = Depends(get_current_user),
) -> ActivityResponse:
    events, total = audit_logger.list_events(limit=limit, decision=decision)
    return ActivityResponse(events=events, total=total)
