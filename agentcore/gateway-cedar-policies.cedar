// Optional Amazon Bedrock AgentCore Gateway Cedar Policies (defense-in-depth)
// Enforces read-only document retrieval, denies restricted records, and enforces R08 cohort checks.

permit(
    principal,
    action == AgentCore::Action::"s3docs___list_authorized_documents",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:<REGION>:<ACCOUNT_ID>:gateway/<GATEWAY_ID>"
);

permit(
    principal,
    action == AgentCore::Action::"s3docs___get_authorized_document",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:<REGION>:<ACCOUNT_ID>:gateway/<GATEWAY_ID>"
)
when {
    context.input.doc_id != "DOC-PAYROLL-2026" &&
    context.input.doc_id != "DOC-EXEC-BOARD-2026"
};

forbid(
    principal,
    action == AgentCore::Action::"s3docs___get_authorized_document",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:<REGION>:<ACCOUNT_ID>:gateway/<GATEWAY_ID>"
)
when {
    context.input.doc_id == "DOC-PAYROLL-2026" ||
    context.input.doc_id == "DOC-EXEC-BOARD-2026"
};

forbid(
    principal,
    action == AgentCore::Action::"s3docs___get_department_compensation_summary",
    resource == AgentCore::Gateway::"arn:aws:bedrock-agentcore:<REGION>:<ACCOUNT_ID>:gateway/<GATEWAY_ID>"
)
when {
    context.input.department == "Corporate Strategy"
};
