# AWS Builder Center Challenge Submission — Redacted

- **Challenge:** Agents, your rules: Bedrock Managed Agents build
- **Project Name:** Redacted
- **Tagline:** Not everything needs to be known.

## What Was Built

**Redacted** is a workplace document assistant designed to demonstrate deterministic policy enforcement around **Amazon Bedrock AgentCore Managed Harness**. Rather than relying on system prompts alone, authorization happens **before retrieval** on the trusted backend and inside AgentCore lifecycle boundaries.

### Key Components
1. **Amazon Bedrock AgentCore Managed Harness (`agentcore/`, `backend/agent.py`)**:
   - Uses official `bedrock-agentcore-control` (`create_harness`, `update_harness`, `get_harness`) and `bedrock-agentcore` (`invoke_harness`) Boto3 APIs.
   - Explicitly pins `allowedTools` to four read-only `inline_function` tools (`@list_authorized_documents`, `@search_authorized_documents`, `@get_authorized_document`, `@get_department_compensation_summary`), removing `shell`, `read`, `write`, `edit`, `web_fetch`, `subagent`, browser, and code interpreter.
   - Integrates Amazon Bedrock Guardrails (`guardrailConfig` via `converse_stream`) and AWS Lambda Lifecycle Hooks (`beforeInvocation`, `beforeToolCall`, `afterToolCall`, `afterInvocation` with `failureMode="deny"`).
2. **Authorization-Before-Retrieval Policy Engine (`backend/authorization.py`, `backend/guardrails.py`, `backend/documents.py`, `backend/audit.py`)**:
   - Server-signed HMAC-SHA256 authentication.
   - Deterministic rule engine enforcing `R01`–`R10`, including k-anonymity (`n >= 5`) for departmental compensation stats (`R08`) and cumulative session exfiltration lockouts (`R04`).
   - Untrusted document sanitizer neutralizing embedded prompt-injection payloads (`R05`) and scanning outputs for plaintext or Base64-encoded compensation leaks (`R03`).
   - Sensitive-data-scrubbed audit logger writing to SQLite and Amazon CloudWatch Logs (`R10`).
3. **Enterprise Document Workspace UI (`frontend/src/`)**:
   - Classic minimal white, black, and charcoal UI using Inter and Playfair Display typography with black redaction bars.
   - Four focused pages: `Workspace.tsx`, `Records.tsx`, `BoundaryTests.tsx`, and `Activity.tsx`.
   - Honest AWS status reporting: unavailable AWS credentials surface an explicit error and `INCONCLUSIVE` status on Boundary Tests rather than fabricated results.

## Verification Transparency

- **Executed & Verified Locally:** All Python security policy tests, `botocore==1.44.12` AgentCore service-model contract tests (`Stubber`), FastAPI API tests (`tests/`), and the React/TypeScript production build (`vite build`).
- **Requires Your AWS Account to Execute Live:** Deploying AWS resources (`infrastructure/deployment/deploy_aws.py` — S3 bucket, IAM roles, Bedrock Guardrail, Lambda functions, CloudWatch log group, and Bedrock AgentCore Managed Harness) and running live end-to-end boundary tests (`infrastructure/deployment/run_live_boundary_tests.py` or the Boundary Tests page).
