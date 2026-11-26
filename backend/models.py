"""Pydantic schemas for Redacted API requests, responses, and telemetry."""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class UserProfile(BaseModel):
    user_id: str
    username: str
    display_name: str
    title: str
    role: str
    department: str
    clearance: Literal["public", "internal", "confidential", "restricted"]


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_at: str
    user: UserProfile


class DemoAccountInfo(BaseModel):
    username: str
    display_name: str
    title: str
    role: str
    department: str
    clearance: str


class ChatMessageInput(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=4000)
    session_id: Optional[str] = Field(default=None, max_length=100)


class CitationRef(BaseModel):
    doc_id: str
    title: str
    access_level: str
    source: str


class SecurityDecisionDetail(BaseModel):
    decision: Literal["ALLOW", "DENY", "BLOCKED", "ERROR"]
    triggered_rules: List[str] = Field(default_factory=list)
    reason: str
    request_id: str
    guardrail_intervened: bool = False
    hook_events: List[Dict[str, Any]] = Field(default_factory=list)
    tool_calls_attempted: List[Dict[str, Any]] = Field(default_factory=list)
    unauthorized_tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    stop_reason: Optional[str] = None


class ChatResponse(BaseModel):
    request_id: str
    session_id: str
    answer: Optional[str] = None
    refused: bool = False
    citations: List[CitationRef] = Field(default_factory=list)
    authorized_documents: List[str] = Field(default_factory=list)
    security: SecurityDecisionDetail
    aws_metadata: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = None


class RecordSummary(BaseModel):
    doc_id: str
    title: str
    category: str
    access_level: Literal["public", "internal", "confidential", "restricted"]
    owner: str
    last_updated: str
    accessible: bool
    redacted: bool
    summary: str
    content: Optional[str] = None
    denial_rule: Optional[str] = None
    denial_reason: Optional[str] = None


class RecordsListResponse(BaseModel):
    organization: str
    user_clearance: str
    records: List[RecordSummary]


class BoundaryTestCase(BaseModel):
    test_id: str
    title: str
    category: Literal["adversarial", "legitimate"]
    prompts: List[str]
    expected_behavior: str
    expected_rules: List[str]
    target_doc_ids: List[str] = Field(default_factory=list)


class BoundaryTestResult(BaseModel):
    test_id: str
    title: str
    category: Literal["adversarial", "legitimate"]
    prompts: List[str]
    actual_response: Optional[str] = None
    expected_behavior: str
    expected_rules: List[str]
    triggered_rules: List[str] = Field(default_factory=list)
    status: Literal["pass", "fail", "inconclusive"]
    evaluation_reason: str
    tool_calls_attempted: List[Dict[str, Any]] = Field(default_factory=list)
    unauthorized_tool_calls: List[Dict[str, Any]] = Field(default_factory=list)
    unauthorized_data_accessed: bool = False
    guardrail_intervened: bool = False
    hook_events: List[Dict[str, Any]] = Field(default_factory=list)
    request_ids: List[str] = Field(default_factory=list)
    executed_at: str
    error: Optional[str] = None


class RunTestsRequest(BaseModel):
    test_ids: Optional[List[str]] = None


class RunTestsResponse(BaseModel):
    aws_connected: bool
    harness_arn: str
    executed_at: str
    summary: Dict[str, int]
    results: List[BoundaryTestResult]


class ActivityEvent(BaseModel):
    id: int
    timestamp: str
    request_id: str
    user_id: str
    user_role: str
    operation: str
    access_decision: Literal["ALLOW", "DENY", "BLOCKED", "ERROR"]
    triggered_rule: str
    reason: str
    doc_id: Optional[str] = None
    tool_name: Optional[str] = None
    aws_trace_id: Optional[str] = None


class ActivityResponse(BaseModel):
    events: List[ActivityEvent]
    total: int


class AwsStatusResponse(BaseModel):
    aws_connected: bool
    region: str
    account_id: Optional[str] = None
    caller_arn: Optional[str] = None
    harness_configured: bool
    harness_arn: str
    harness_status: Optional[str] = None
    guardrail_configured: bool
    guardrail_id: str
    s3_bucket_configured: bool
    s3_documents_bucket: str
    cloudwatch_log_group: str
    allowed_tools: List[str]
    error: Optional[str] = None
