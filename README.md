# Redacted

**Not everything needs to be known.**

An enterprise workplace document assistant built for the AWS Builder Center challenge *"Agents, your rules: Bedrock Managed Agents build"*. **Redacted** integrates directly with **Amazon Bedrock AgentCore Managed Harness**, **Amazon Bedrock Guardrails**, **AWS Lambda**, **Amazon S3**, **AWS IAM**, and **Amazon CloudWatch** to enforce authorization before retrieval across mandatory rules **R01–R10**.

---

## Project Layout

```text
redacted/
├── frontend/
│   └── src/
│       ├── Workspace.tsx
│       ├── Records.tsx
│       ├── BoundaryTests.tsx
│       └── Activity.tsx
├── backend/
│   ├── main.py
│   ├── agent.py
│   ├── authorization.py
│   ├── guardrails.py
│   ├── documents.py
│   └── audit.py
├── agentcore/
├── infrastructure/
│   ├── iam-policy.json
│   └── deployment/
├── data/
├── tests/
├── README.md
├── RULES.md
├── SECURITY.md
├── STRESS_TESTS.md
├── SUBMISSION.md
├── LICENSE
├── .env.example
└── .gitignore
```

---

## Core Capabilities

- **Workspace ([Workspace.tsx](frontend/src/Workspace.tsx)):** Server-authenticated assistant interface backed by `bedrock-agentcore` `InvokeHarness` with conversation history, authorized document references, source citations, policy refusals, and live security decision telemetry.
- **Records ([Records.tsx](frontend/src/Records.tsx)):** Categorized synthetic company records (*Annual Financial Report*, *Quarterly Revenue Report*, *Employee Handbook*, *Payroll Records*, *Confidential Contracts*, *Internal Executive Records*) with strict server-side redaction — unauthorized clients never receive restricted document contents.
- **Boundary Tests ([BoundaryTests.tsx](frontend/src/BoundaryTests.tsx)):** 10 adversarial tests (prompt injection, role spoofing, record deletion, bulk export, Base64 salary bypass, untrusted embedded document directive, 1-employee department inference, incremental multi-turn extraction, revenue fabrication, and audit pretext) plus 3 legitimate baseline requests, with JSON export. Never fabricates passing results when AWS is disconnected.
- **Activity ([Activity.tsx](frontend/src/Activity.tsx)):** Auditable security decision log (`Timestamp`, `Request ID`, `Operation`, `Access Decision`, `Triggered Rule`, `Reason`) scrubbed of sensitive data (`R10`) and forwarded to Amazon CloudWatch Logs when configured.

---

## Architecture & Mandatory Rules

- Architecture details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Mandatory rules R01–R10: [RULES.md](RULES.md)
- Threat model & IAM boundaries: [SECURITY.md](SECURITY.md)
- Adversarial test matrix: [STRESS_TESTS.md](STRESS_TESTS.md)

---

## Synthetic Evaluation Accounts

These fictional accounts exist in `backend/authorization.py` and are authenticated server-side with PBKDF2-HMAC-SHA256 + HMAC-SHA256 Bearer tokens:

| Username | Role / Dept | Clearance | Password |
| :--- | :--- | :--- | :--- |
| `claire.vance` | Analyst (`finance`) | `internal` | `Redacted-Analyst-2026!` |
| `marcus.chen` | Operations (`operations`) | `internal` | `Redacted-Ops-2026!` |
| `david.okafor` | General Counsel (`legal`) | `confidential` | `Redacted-Legal-2026!` |
| `helena.park` | Compliance (`compliance`) | `internal` | `Redacted-Audit-2026!` |

*Note: No interactive workspace persona is permitted to retrieve `DOC-PAYROLL-2026` or `DOC-EXEC-BOARD-2026` (`restricted`).*

---

## Windows Installation & Local Run Commands

> **PowerShell Note:** If Windows PowerShell execution policy blocks `npm.ps1`, invoke `npm.cmd` directly as shown below.

### 1. Backend Setup & Automated Local Tests

```powershell
python -m venv backend\.venv
.\backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
.\backend\.venv\Scripts\python.exe -m pytest tests -v
```

### 2. Frontend Setup & Production Build

```powershell
cd frontend
npm.cmd install
npm.cmd run build
cd ..
```

### 3. Run Locally (Development)

Terminal 1 (FastAPI Backend on port `8000`):
```powershell
.\backend\.venv\Scripts\python.exe -m uvicorn main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

Terminal 2 (React + Vite Frontend on port `5173`):
```powershell
cd frontend
npm.cmd run dev
```

Open `http://localhost:5173` in your browser.

---

## AWS Deployment (Requires Your AWS Account)

### Prerequisites
1. Configure AWS credentials (`aws login` or `aws configure`) in a Region supporting Amazon Bedrock AgentCore Harness (e.g., `us-west-2` or `us-east-1`).
2. Ensure Amazon Bedrock model access is enabled in your Region for `us.anthropic.claude-sonnet-4-5-20250514-v1:0` (or pass `--model-id` with another Bedrock model ID).
3. Ensure your deploying IAM principal has permissions to create S3 buckets, IAM roles/inline policies, Lambda functions, Bedrock Guardrails, CloudWatch log groups, and AgentCore Harnesses (`bedrock-agentcore:CreateHarness`, `bedrock-agentcore:CreateAgentRuntime`, `bedrock-agentcore:CreateMemory`, `iam:PassRole`).

### Deploy All AWS Resources & Managed Harness

```powershell
.\backend\.venv\Scripts\python.exe infrastructure\deployment\deploy_aws.py --region us-west-2
```

This script:
1. Creates a private, encrypted, versioned Amazon S3 bucket (`redacted-docs-<account>-<region>`) and uploads `data/documents/`.
2. Creates CloudWatch log group `/aws/redacted/security-audit`.
3. Creates & publishes the Amazon Bedrock Guardrail (`redacted-enterprise-guardrail`).
4. Deploys Lambda functions `redacted-harness-hook` (lifecycle hook validator) and `redacted-doc-retriever` (read-only S3 retriever).
5. Creates `RedactedAgentCoreHarnessExecutionRole` (with explicit `Deny` on `s3:*`, `sts:AssumeRole`, and `InvokeAgentRuntimeCommand`).
6. Applies least-privilege S3 bucket policy (`infrastructure/s3-bucket-policy.json`).
7. Creates/updates the **Amazon Bedrock AgentCore Managed Harness** (`redacted_document_assistant`), waits until `READY`, and writes `.env` + `aws_outputs.json`.

### Run Live Boundary Tests Against Deployed AWS Harness

```powershell
.\backend\.venv\Scripts\python.exe infrastructure\deployment\run_live_boundary_tests.py
```

Or restart the backend (so it loads the generated `.env`), open `http://localhost:5173`, navigate to **Boundary Tests**, and click **Run All Tests**.

---

## AWS Cost Warnings & Cleanup

### Cost Warnings
Deploying and invoking AWS resources incurs charges billed to your AWS account:
- **Amazon Bedrock AgentCore Runtime / Managed Harness:** While the Harness configuration layer has no separate surcharge, each active session starts an isolated microVM billed per consumed vCPU-second and peak GB-second (`idleRuntimeSessionTimeout` is set to 300 seconds to limit idle memory billing).
- **AgentCore Managed Memory:** Configured with `eventExpiryDuration: 3` days; short-term memory events and summarization storage incur standard AgentCore Memory charges.
- **Amazon Bedrock Model Inference & Guardrails:** Token input/output charges apply per turn (including tool definition tokens), plus Bedrock Guardrails assessment units.
- **AWS Lambda, Amazon S3, and CloudWatch Logs:** Standard invocation, storage, and log ingestion/retention rates apply.

### Cleanup Instructions (Tear Down All AWS Resources)

Run the cleanup script when finished testing to avoid ongoing charges:

```powershell
.\backend\.venv\Scripts\python.exe infrastructure\deployment\cleanup_aws.py --region us-west-2
```

This removes the AgentCore Managed Harness (and its managed memory via `deleteManagedMemory=True`), the Bedrock Guardrail, both Lambda functions, the three IAM roles, the S3 bucket (all object versions emptied), and the CloudWatch audit log group.

---

## License

MIT License — see [LICENSE](LICENSE).
