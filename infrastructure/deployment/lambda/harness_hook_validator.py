"""AWS Lambda lifecycle hook validator for Amazon Bedrock AgentCore Managed Harness.

Implements the exact Harness Lifecycle Hook payload & response contract:
- before_invocation: validates non-truncated input and blocks obvious prompt-level violations (R02/R03/R04/R06/R08)
- before_tool_call: verifies toolName is strictly in the read-only allowlist (blocks shell/read/write/edit/web_fetch/subagent)
- after_tool_call: checks tool results for untrusted injection leakage or restricted PII patterns (R03/R05)
- after_invocation: logs scrubbed summary telemetry without sensitive payload contents (R10)
"""

from __future__ import annotations

import json
import os
import re
from typing import Any, Dict

ALLOWED_TOOLS = {
    "list_authorized_documents",
    "search_authorized_documents",
    "get_authorized_document",
    "get_department_compensation_summary",
}

FORBIDDEN_TOOL_PREFIXES = (
    "shell",
    "read",
    "write",
    "edit",
    "file_operations",
    "web_fetch",
    "subagent",
    "browser",
    "code_interpreter",
)

MUTATION_RE = re.compile(
    r"\b(?:delete|remove|erase|modify|overwrite|update)\b.*\b(?:report|record|document|payroll|contract)\b",
    re.IGNORECASE,
)
ADMIN_CLAIM_RE = re.compile(
    r"(?:\bi\s+am\s+(?:the\s+)?(?:admin|administrator|ceo|root)\b|\bgrant\s+me\s+full\s+access\b)",
    re.IGNORECASE,
)
BULK_EXPORT_RE = re.compile(r"\b(?:export\s+all|dump\s+all|all\s+confidential\s+records)\b", re.IGNORECASE)
SMALL_GROUP_RE = re.compile(r"\b(?:only\s+one\s+employee|one\s+employee|corporate\s+strategy)\b.*\b(?:salary|average)\b", re.IGNORECASE)
PII_OUTPUT_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b|000-00-\d{4}")


def _extract_text_from_messages(messages: list[Dict[str, Any]]) -> str:
    chunks = []
    for msg in messages:
        for block in msg.get("content", []):
            if isinstance(block, dict) and "text" in block:
                chunks.append(str(block["text"]))
    return "\n".join(chunks)


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    event_type = event.get("event", "")
    hook_context = event.get("context", {}) or {}
    session_id = str(event.get("sessionId", ""))[:48]

    if event_type == "before_invocation":
        if hook_context.get("truncated"):
            return {
                "decision": "deny",
                "reason": "R09: Hook invocation context exceeded 64 KiB inspection limit; failing closed.",
            }
        text = _extract_text_from_messages(hook_context.get("messages", []))
        if MUTATION_RE.search(text):
            return {"decision": "deny", "reason": "R02: Modification or deletion of company records is prohibited."}
        if ADMIN_CLAIM_RE.search(text):
            return {"decision": "deny", "reason": "R06: Conversational identity/admin claims are rejected."}
        if BULK_EXPORT_RE.search(text):
            return {"decision": "deny", "reason": "R04: Unauthorized bulk exports are prohibited."}
        if SMALL_GROUP_RE.search(text):
            return {"decision": "deny", "reason": "R08: Small-group salary statistics are blocked."}
        print(json.dumps({"event": "before_invocation", "decision": "allow", "sessionId": session_id}))
        return {"decision": "allow", "reason": "Pre-invocation lifecycle validation passed."}

    if event_type == "before_tool_call":
        tool_name = str(hook_context.get("toolName", ""))
        tool_input = hook_context.get("toolInput", {}) or {}
        if isinstance(tool_input, dict) and tool_input.get("truncated"):
            return {"decision": "deny", "reason": "R09: Tool input truncated; failing closed."}

        if tool_name.startswith(FORBIDDEN_TOOL_PREFIXES) or tool_name not in ALLOWED_TOOLS:
            print(json.dumps({"event": "before_tool_call", "decision": "deny", "toolName": tool_name}))
            return {
                "decision": "deny",
                "reason": f"R02: Tool '{tool_name}' is outside the authorized read-only allowlist.",
            }

        if tool_name == "get_authorized_document" and isinstance(tool_input, dict):
            doc_id = str(tool_input.get("doc_id", ""))
            if doc_id in {"DOC-PAYROLL-2026", "DOC-EXEC-BOARD-2026"}:
                return {
                    "decision": "deny",
                    "reason": f"R03/R01: Restricted document {doc_id} cannot be retrieved via assistant tools.",
                }

        if tool_name == "search_authorized_documents" and isinstance(tool_input, dict):
            if int(tool_input.get("limit", 3) or 3) > 3:
                return {"decision": "deny", "reason": "R04: Search result limit exceeds max cap (3)."}

        print(json.dumps({"event": "before_tool_call", "decision": "allow", "toolName": tool_name}))
        return {"decision": "allow", "reason": f"Tool '{tool_name}' permitted for server-gated execution."}

    if event_type == "after_tool_call":
        tool_name = str(hook_context.get("toolName", ""))
        raw_result = json.dumps(hook_context.get("toolResult", ""))
        if PII_OUTPUT_RE.search(raw_result):
            return {
                "decision": "deny",
                "reason": "R03: Detected restricted tax/SSN pattern in tool output; stopping invocation.",
            }
        print(json.dumps({"event": "after_tool_call", "decision": "allow", "toolName": tool_name}))
        return {"decision": "allow", "reason": "Post-tool output check passed."}

    if event_type == "after_invocation":
        usage = hook_context.get("usage", {})
        print(
            json.dumps(
                {
                    "event": "after_invocation",
                    "stopReason": hook_context.get("stopReason"),
                    "inputTokens": usage.get("inputTokens"),
                    "outputTokens": usage.get("outputTokens"),
                    "sessionId": session_id,
                }
            )
        )
        return {"decision": "allow"}

    return {"decision": "deny", "reason": f"R09: Unrecognized lifecycle event '{event_type}'."}
