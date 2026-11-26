# Security Architecture & Threat Model — Redacted

## Defense-in-Depth Control Plane

1. **No Implicit Trust in Prompts**: Prompts and Bedrock foundation model reasoning are treated as untrusted orchestration signals. Every security boundary is enforced outside the model in deterministic Python (`backend/authorization.py`, `backend/guardrails.py`), AWS IAM (`infrastructure/`), Bedrock Guardrails (`agentcore/guardrail-config.json`), and Lambda Lifecycle Hooks (`infrastructure/deployment/lambda/harness_hook_validator.py`).
2. **Server-Side Cryptographic Authentication**:
   - Credentials are verified against salted PBKDF2-HMAC-SHA256 hashes in `backend/authorization.py`.
   - Clients never pass `role` or `clearance` headers; the server resolves authoritative `UserRecord` strictly from the signed token's `sub` claim.
   - `runtimeSessionId` passed to `InvokeHarness` is prefixed and bound to `user_id`; cross-user session reuse raises `PermissionError` (`R09`).
3. **Managed Harness Capability Minimization**:
   - Per `docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-tools.html`, built-in tools (`shell`, `read`, `write`, `edit`, `web_fetch`, `subagent`, `todo_write`) are **disabled** by setting an explicit `allowedTools` list containing only the four read-only `inline_function` tools.
   - `bedrock-agentcore:InvokeAgentRuntimeCommand` and `InvokeAgentRuntimeCommandShell` are explicitly denied in both `infrastructure/harness-execution-policy.json` and `infrastructure/backend-caller-policy.json`.
   - No `s3BucketMount` or `efsAccessPoint` is configured.
4. **IAM Least Privilege**:
   - `RedactedAgentCoreHarnessExecutionRole` has explicit `Deny` on `s3:*` and `sts:AssumeRole`.
   - `RedactedDocRetrieverLambdaRole` has read-only `s3:GetObject` scoped to `documents/*` and explicit `Deny` on `s3:PutObject`, `s3:DeleteObject`, `s3:DeleteObjectVersion`.
   - S3 Bucket Policy (`infrastructure/s3-bucket-policy.json`) enforces TLS (`aws:SecureTransport`) and denies S3 access from the Harness Execution Role.
5. **Amazon Bedrock Guardrails (`agentcore/guardrail-config.json`)**:
   - `PROMPT_ATTACK` content filter (`HIGH` input strength).
   - Topic policies blocking payroll/executive salary extraction, record deletion/bulk export, and conversational privilege escalation.
   - Sensitive Information / PII blocking (`US_SOCIAL_SECURITY_NUMBER`, `US_BANK_ACCOUNT_NUMBER`, `US_BANK_ROUTING_NUMBER`, and custom regex `000-00-\d{4}`).
6. **Input Validation & Shared Responsibility (`harness-security.html`)**:
   - The backend ignores or rejects any client attempt to supply `model`, `additionalParams`, `skills`, `tools`, or `toolUse` blocks; all harness configuration parameters are server-controlled.
7. **Sanitized Telemetry (R10)**:
   - `scrub_sensitive_text` redacts tax IDs, salary amounts, field key-value leaks, and long Base64 strings prior to persistence in SQLite and Amazon CloudWatch Logs.
   - Restricted records (`DOC-PAYROLL-2026`, `DOC-EXEC-BOARD-2026`) never leave the backend or S3 `restricted/` prefix for unauthorized users and are excluded from `frontend/src/`.

## Credential Hygiene

- AWS credentials reside exclusively on the backend host (`.env` / IAM role / AWS CLI profile).
- Never expose `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, or `REDACTED_AUTH_SECRET` to Vite (`VITE_*` variables are forbidden for secrets).
