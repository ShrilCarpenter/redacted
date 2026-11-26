"""Backend configuration and security constants for Redacted."""

from __future__ import annotations

from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = PROJECT_ROOT / "data" / "documents"
AGENTCORE_DIR = PROJECT_ROOT / "agentcore"
INFRA_DIR = PROJECT_ROOT / "infrastructure"

# Strict server-controlled tool allowlist passed to AgentCore Managed Harness.
# Explicitly excludes built-in shell, read, write, edit, file_operations,
# web_fetch, subagent, todo_write, browser, and code_interpreter.
HARNESS_ALLOWED_TOOLS: List[str] = [
    "@list_authorized_documents",
    "@search_authorized_documents",
    "@get_authorized_document",
    "@get_department_compensation_summary",
]

MIN_ANONYMITY_GROUP_SIZE: int = 5
MAX_DOCS_PER_CALL: int = 3
MAX_DOCS_PER_SESSION: int = 6
MAX_UNAUTHORIZED_ATTEMPTS_PER_SESSION: int = 3

CLEARANCE_LEVELS = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}


class Settings(BaseSettings):
    """Application settings loaded from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=(str(PROJECT_ROOT / ".env"), str(PROJECT_ROOT / "backend" / ".env")),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    aws_region: str = "us-west-2"
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_profile: str | None = None

    agentcore_harness_arn: str = ""
    agentcore_harness_id: str = ""
    agentcore_harness_qualifier: str = "DEFAULT"
    agentcore_execution_role_arn: str = ""

    bedrock_model_id: str = "us.anthropic.claude-sonnet-4-5-20250514-v1:0"
    bedrock_guardrail_id: str = ""
    bedrock_guardrail_version: str = "1"

    s3_documents_bucket: str = ""
    s3_documents_prefix: str = "documents/"
    document_source_mode: str = "auto"

    lambda_retriever_arn: str = ""
    lambda_hook_arn: str = ""

    cloudwatch_log_group: str = "/aws/redacted/security-audit"
    cloudwatch_log_stream: str = "backend-security-events"

    redacted_auth_secret: str = "local-dev-ephemeral-signing-key-change-in-prod"
    redacted_audit_db_path: str = str(PROJECT_ROOT / "backend" / "data" / "audit_events.db")
    redacted_cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    redacted_port: int = 8000

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.redacted_cors_origins.split(",") if o.strip()]


settings = Settings()
