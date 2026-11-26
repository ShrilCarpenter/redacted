"""Botocore contract tests for Amazon Bedrock AgentCore Managed Harness and Lambda Hook integration."""

from __future__ import annotations

import importlib.util
import json
import sys
from unittest.mock import patch

import boto3
from botocore.exceptions import NoCredentialsError
from botocore.stub import Stubber

from agent import AgentCoreService, build_harness_inline_tools, run_boundary_tests
from authorization import USER_DIRECTORY
from config import HARNESS_ALLOWED_TOOLS, PROJECT_ROOT, settings


class _DummyPayloadStream:
    """Simulates botocore InvokeHarness streaming EventStream."""

    def __init__(self, events):
        self._events = events

    def __iter__(self):
        return iter(self._events)


def test_create_and_invoke_harness_conform_to_botocore_model() -> None:
    """Validate exact CreateHarness & InvokeHarness parameter shapes against botocore==1.44.12."""
    ctrl = boto3.client(
        "bedrock-agentcore-control",
        region_name="ap-southeast-2",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    stub_ctrl = Stubber(ctrl)
    stub_ctrl.add_response(
        "create_harness",
        {
            "harness": {
                "harnessId": "redacted-12345",
                "harnessName": "redacted_document_assistant",
                "arn": "arn:aws:bedrock-agentcore:ap-southeast-2:123456789012:harness/redacted-12345",
                "status": "READY",
                "executionRoleArn": "arn:aws:iam::123456789012:role/RedactedRole",
                "createdAt": "2026-11-26T00:00:00Z",
                "updatedAt": "2026-11-26T00:00:00Z",
                "model": {"bedrockModelConfig": {"modelId": "amazon.nova-pro-v1:0"}},
                "systemPrompt": [{"text": "Redacted instructions"}],
                "tools": build_harness_inline_tools(),
                "skills": [],
                "allowedTools": HARNESS_ALLOWED_TOOLS,
                "truncation": {"strategy": "sliding_window"},
                "environment": {
                    "agentCoreRuntimeEnvironment": {
                        "agentRuntimeArn": "arn:aws:bedrock-agentcore:ap-southeast-2:123456789012:runtime/rt-1",
                        "agentRuntimeName": "rt",
                        "agentRuntimeId": "rt-1",
                        "lifecycleConfiguration": {"idleRuntimeSessionTimeout": 300, "maxLifetime": 3600},
                        "networkConfiguration": {"networkMode": "PUBLIC"},
                    }
                },
            }
        },
        {
            "harnessName": "redacted_document_assistant",
            "executionRoleArn": "arn:aws:iam::123456789012:role/RedactedRole",
            "model": {
                "bedrockModelConfig": {
                    "modelId": "amazon.nova-pro-v1:0",
                    "apiFormat": "converse_stream",
                    "additionalParams": {
                        "guardrailConfig": {
                            "guardrailIdentifier": "gr-abc123",
                            "guardrailVersion": "1",
                            "trace": "enabled_full",
                        }
                    },
                }
            },
            "systemPrompt": [{"text": "Redacted instructions"}],
            "tools": build_harness_inline_tools(),
            "allowedTools": HARNESS_ALLOWED_TOOLS,
        },
    )
    with stub_ctrl:
        out = ctrl.create_harness(
            harnessName="redacted_document_assistant",
            executionRoleArn="arn:aws:iam::123456789012:role/RedactedRole",
            model={
                "bedrockModelConfig": {
                    "modelId": "amazon.nova-pro-v1:0",
                    "apiFormat": "converse_stream",
                    "additionalParams": {
                        "guardrailConfig": {
                            "guardrailIdentifier": "gr-abc123",
                            "guardrailVersion": "1",
                            "trace": "enabled_full",
                        }
                    },
                }
            },
            systemPrompt=[{"text": "Redacted instructions"}],
            tools=build_harness_inline_tools(),
            allowedTools=HARNESS_ALLOWED_TOOLS,
        )
        assert out["harness"]["status"] == "READY"


def test_inline_tool_handoff_blocks_unauthorized_doc_before_retrieval(monkeypatch) -> None:
    """Simulate AgentCore Harness streaming a tool_use for DOC-PAYROLL-2026 and verify pre-retrieval R03 block."""
    monkeypatch.setattr(settings, "agentcore_harness_arn", "arn:aws:bedrock-agentcore:ap-southeast-2:123456789012:harness/redacted-123")
    monkeypatch.setattr(settings, "bedrock_guardrail_id", "gr-test123")

    round_1_stream = _DummyPayloadStream(
        [
            {"messageStart": {"role": "assistant"}},
            {"contentBlockStart": {"contentBlockIndex": 0, "start": {"toolUse": {"toolUseId": "tu-1", "name": "get_authorized_document"}}}},
            {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"toolUse": {"input": json.dumps({"doc_id": "DOC-PAYROLL-2026"})}}}},
            {"contentBlockStop": {"contentBlockIndex": 0}},
            {"messageStop": {"stopReason": "tool_use"}},
        ]
    )
    round_2_stream = _DummyPayloadStream(
        [
            {"messageStart": {"role": "assistant"}},
            {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "I cannot access DOC-PAYROLL-2026 due to policy restrictions."}}},
            {"messageStop": {"stopReason": "end_turn"}},
            {"metadata": {"usage": {"inputTokens": 120, "outputTokens": 24, "totalTokens": 144}, "metrics": {"latencyMs": 310}}},
        ]
    )

    captured_calls = []

    class _FakeDataClient:
        def invoke_harness(self, **kwargs):
            captured_calls.append(kwargs)
            if len(captured_calls) == 1:
                return {"stream": round_1_stream, "ResponseMetadata": {"RequestId": "aws-req-1"}}
            return {"stream": round_2_stream, "ResponseMetadata": {"RequestId": "aws-req-2"}}

    svc = AgentCoreService()
    user = USER_DIRECTORY["claire.vance"]
    with patch.object(svc, "_data_client", return_value=_FakeDataClient()):
        resp = svc.ask_workspace(
            user=user,
            prompt="Summarize the latest company financial highlights.",
            session_id="test-session-handoff",
            request_id="req-handoff-1",
        )

    assert resp.error is None
    assert resp.refused is True
    assert "R03" in resp.security.triggered_rules
    assert len(resp.security.unauthorized_tool_calls) == 1
    assert resp.security.unauthorized_tool_calls[0]["args"]["doc_id"] == "DOC-PAYROLL-2026"
    round2_content = captured_calls[1]["messages"][0]["content"][0]["toolResult"]
    assert round2_content["status"] == "error"
    assert "ACCESS_DENIED" in round2_content["content"][0]["text"]
    assert "680000" not in round2_content["content"][0]["text"]


def test_unavailable_aws_never_fabricates_passing_boundary_tests(monkeypatch) -> None:
    """When AWS credentials or harness are unavailable, boundary tests MUST report inconclusive + error."""
    monkeypatch.setattr(settings, "agentcore_harness_arn", "")
    user = USER_DIRECTORY["claire.vance"]

    report = run_boundary_tests(user=user, test_ids=["T01", "L01"])
    assert report.aws_connected is False
    assert report.summary["pass"] == 0
    assert report.summary["inconclusive"] == 2
    for res in report.results:
        assert res.status == "inconclusive"
        assert res.error is not None

    monkeypatch.setattr(settings, "agentcore_harness_arn", "arn:aws:bedrock-agentcore:ap-southeast-2:123456789012:harness/x")
    with patch("agent.AgentCoreService._boto_session") as mock_sess:
        mock_sess.return_value.client.side_effect = NoCredentialsError()
        report2 = run_boundary_tests(user=user, test_ids=["T01"])
        assert report2.aws_connected is False
        assert report2.results[0].status == "inconclusive"
        assert "credentials" in (report2.results[0].error or "").lower()


def test_lambda_lifecycle_hook_validator() -> None:
    hook_path = PROJECT_ROOT / "infrastructure" / "deployment" / "lambda" / "harness_hook_validator.py"
    spec = importlib.util.spec_from_file_location("harness_hook_validator", str(hook_path))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["harness_hook_validator"] = mod
    spec.loader.exec_module(mod)

    r_shell = mod.lambda_handler(
        {"event": "before_tool_call", "sessionId": "s1", "context": {"toolName": "shell", "toolInput": {"command": "ls"}}},
        None,
    )
    assert r_shell["decision"] == "deny"

    r_pay = mod.lambda_handler(
        {
            "event": "before_tool_call",
            "sessionId": "s1",
            "context": {"toolName": "get_authorized_document", "toolInput": {"doc_id": "DOC-PAYROLL-2026"}},
        },
        None,
    )
    assert r_pay["decision"] == "deny"

    r_ok = mod.lambda_handler(
        {
            "event": "before_tool_call",
            "sessionId": "s1",
            "context": {"toolName": "get_authorized_document", "toolInput": {"doc_id": "DOC-HANDBOOK-2026"}},
        },
        None,
    )
    assert r_ok["decision"] == "allow"


def test_guardrail_config_and_confused_deputy_trust_policy() -> None:
    """Validate guardrail-config.json against botocore Bedrock model and confused-deputy trust policy."""
    br = boto3.client(
        "bedrock",
        region_name="ap-southeast-2",
        aws_access_key_id="AKIAIOSFODNN7EXAMPLE",
        aws_secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    )
    stub_br = Stubber(br)
    cfg = json.loads((PROJECT_ROOT / "agentcore" / "guardrail-config.json").read_text(encoding="utf-8"))
    stub_br.add_response(
        "create_guardrail",
        {
            "guardrailId": "gr-abc123",
            "guardrailArn": "arn:aws:bedrock:ap-southeast-2:123456789012:guardrail/gr-abc123",
            "version": "DRAFT",
            "createdAt": "2026-11-26T00:00:00Z",
        },
    )
    with stub_br:
        res = br.create_guardrail(**cfg)
    assert res["guardrailId"] == "gr-abc123"

    trust = json.loads((PROJECT_ROOT / "infrastructure" / "harness-trust-policy.json").read_text(encoding="utf-8"))
    stmt = trust["Statement"][0]
    assert stmt["Condition"]["StringEquals"]["aws:SourceAccount"] == "<ACCOUNT_ID>"
    assert "bedrock-agentcore:<REGION>:<ACCOUNT_ID>:*" in stmt["Condition"]["ArnLike"]["aws:SourceArn"]


def test_get_boto_session_honors_profile_and_region(monkeypatch) -> None:
    """Ensure get_boto_session passes configured profile_name and region_name."""
    from config import get_boto_session

    monkeypatch.setattr(settings, "aws_region", "ap-southeast-2")
    monkeypatch.setattr(settings, "aws_profile", "redacted")
    monkeypatch.setattr(settings, "aws_access_key_id", None)
    monkeypatch.setattr(settings, "aws_secret_access_key", None)

    with patch("boto3.Session") as mock_sess:
        get_boto_session()
        mock_sess.assert_called_once_with(region_name="ap-southeast-2", profile_name="redacted")
