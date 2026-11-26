# Architecture Documentation — Redacted

Tagline: **Not everything needs to be known.**

## 1. System Overview

**Redacted** is an enterprise workplace document assistant built on **Amazon Bedrock AgentCore Managed Harness**, **Amazon Bedrock Guardrails**, **AWS Lambda**, **Amazon S3**, **AWS IAM**, and **Amazon CloudWatch**.

Its central architectural invariant is **authorization before retrieval**: the LLM inside the Managed Harness never holds direct access to Amazon S3, filesystem storage, or a command shell. Instead, all document retrieval passes through server-authenticated, deterministic policy checkpoints before any record leaves S3.

```
[React + Vite UI (frontend/src/*)]
       │ HTTPS + Bearer HMAC-SHA256 Session Token (No AWS creds in browser)
       ▼
[FastAPI Backend (backend/main.py)] ──► [Auth & Policy Engine (backend/authorization.py)] (R01-R10, k-anonymity >= 5)
       │
       ├──► [Guardrails & Sanitizer (backend/guardrails.py)] (R03, R05, R07)
       │
       ├──► [Audit Logger (backend/audit.py)] ──► SQLite + Amazon CloudWatch Logs (R10 scrubbed)
       │
       └──► boto3.client("bedrock-agentcore").invoke_harness(...) (backend/agent.py)
                   │
                   ▼
     [Amazon Bedrock AgentCore Managed Harness]
       ├── Firecracker microVM (no S3/EFS mount)
       ├── allowedTools: ONLY @list/search/get_authorized_document + @get_department_compensation_summary
       ├── Explicitly excluded: shell, read, write, edit, file_operations, web_fetch, subagent, browser, code_interpreter
       ├── Bedrock Model (converse_stream) + guardrailConfig (Amazon Bedrock Guardrails)
       └── Lifecycle Hooks (infrastructure/deployment/lambda/harness_hook_validator.py, failureMode="deny")
             ├── beforeInvocation
             ├── beforeToolCall
             ├── afterToolCall
             └── afterInvocation
                   │
                   │ inline_function tool_use handoff (same runtimeSessionId)
                   ▼
     [FastAPI Trusted Tool Executor (backend/documents.py)]
       └── policy_engine.authorize_tool_call(user, session_state, tool, args)
             ├── DENY -> returns ACCESS_DENIED [Rule] (S3 never touched)
             └── ALLOW -> [Read-Only S3 / Lambda Retriever] ──► [R05 Sanitizer] ──► toolResult
```

## 2. Constraining AgentCore Managed Harness Capabilities

Per official Amazon Bedrock AgentCore documentation (`harness-tools.html`, `harness-security.html`), omitting `allowedTools` or setting `["*"]` grants built-in `shell`, `read`, `write`, `edit`, `web_fetch`, and `subagent` tools. **Redacted** explicitly constrains the Managed Harness at five layers:

1. **Tool Surface (`allowedTools`)**: Pinned to `["@list_authorized_documents", "@search_authorized_documents", "@get_authorized_document", "@get_department_compensation_summary"]` in both `CreateHarness` and every `InvokeHarness` request (`backend/config.py`).
2. **Environment Isolation**: No `s3BucketMount`, `s3FilesAccessPoint`, or `efsAccessPoint` is attached (`agentcore/harness-config.json`).
3. **IAM Execution Role (`RedactedAgentCoreHarnessExecutionRole`)**: Explicit `Deny` on `s3:*`, `sts:AssumeRole`, `bedrock-agentcore:InvokeAgentRuntimeCommand`, and `bedrock-agentcore:InvokeAgentRuntimeCommandShell` (`infrastructure/harness-execution-policy.json`).
4. **Caller Input Hardening**: The FastAPI backend accepts only `{prompt, session_id}` from clients and never forwards client-supplied `model`, `systemPrompt`, `tools`, `skills`, `additionalParams`, or `toolUse` blocks to `invoke_harness`.
5. **Lifecycle Hooks (`redacted-harness-hook`)**: Synchronous Lambda hooks with `failureMode: "deny"` enforce tool allowlists and context limits inside the AgentCore execution loop (`infrastructure/deployment/lambda/harness_hook_validator.py`).
