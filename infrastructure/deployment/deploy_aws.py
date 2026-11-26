"""Provision Redacted AWS infrastructure: S3, IAM Roles, Guardrail, Lambda Hooks/Retriever, CloudWatch, and AgentCore Managed Harness.

Usage (Windows PowerShell):
  .\\backend\\.venv\\Scripts\\python.exe infrastructure\\deployment\\deploy_aws.py --region us-west-2
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import zipfile
from pathlib import Path
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
AGENTCORE_DIR = PROJECT_ROOT / "agentcore"
INFRA_DIR = PROJECT_ROOT / "infrastructure"
DEPLOY_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))
sys.path.insert(0, str(DEPLOY_DIR))

from agent import build_harness_inline_tools  # noqa: E402
from upload_dataset import upload_dataset  # noqa: E402


def _zip_lambda_file(src_path: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(src_path, arcname=src_path.name)
    return buf.getvalue()


def _render_policy(template_path: Path, replacements: Dict[str, str]) -> str:
    text = template_path.read_text(encoding="utf-8")
    for k, v in replacements.items():
        text = text.replace(k, v)
    return text


def ensure_s3_bucket(s3: Any, bucket: str, region: str) -> None:
    try:
        s3.head_bucket(Bucket=bucket)
        print(f"[S3] Using existing bucket: {bucket}")
    except ClientError:
        kwargs: Dict[str, Any] = {"Bucket": bucket}
        if region != "us-east-1":
            kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**kwargs)
        print(f"[S3] Created bucket: {bucket}")

    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    s3.put_bucket_encryption(
        Bucket=bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})


def ensure_iam_role(iam: Any, role_name: str, trust_policy: str, inline_policy_name: str, inline_policy: str) -> str:
    try:
        role = iam.get_role(RoleName=role_name)["Role"]
        role_arn = role["Arn"]
        iam.update_assume_role_policy(RoleName=role_name, PolicyDocument=trust_policy)
        print(f"[IAM] Updated role trust policy: {role_name}")
    except iam.exceptions.NoSuchEntityException:
        role = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=trust_policy,
            Description="Least-privilege role for Redacted AWS Bedrock AgentCore project",
        )["Role"]
        role_arn = role["Arn"]
        print(f"[IAM] Created role: {role_name}")
        time.sleep(8)

    iam.put_role_policy(RoleName=role_name, PolicyName=inline_policy_name, PolicyDocument=inline_policy)
    print(f"[IAM] Attached inline policy {inline_policy_name} to {role_name}")
    return role_arn


def ensure_lambda(lam: Any, function_name: str, role_arn: str, src_path: Path, handler: str, env_vars: Dict[str, str]) -> str:
    zip_bytes = _zip_lambda_file(src_path)
    try:
        resp = lam.get_function(FunctionName=function_name)
        lam.update_function_code(FunctionName=function_name, ZipFile=zip_bytes)
        time.sleep(2)
        lam.update_function_configuration(
            FunctionName=function_name,
            Role=role_arn,
            Handler=handler,
            Runtime="python3.12",
            Timeout=15,
            Environment={"Variables": env_vars},
        )
        fn_arn = resp["Configuration"]["FunctionArn"]
        print(f"[Lambda] Updated function: {function_name}")
    except lam.exceptions.ResourceNotFoundException:
        resp = lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler=handler,
            Code={"ZipFile": zip_bytes},
            Timeout=15,
            MemorySize=256,
            Environment={"Variables": env_vars},
        )
        fn_arn = resp["FunctionArn"]
        print(f"[Lambda] Created function: {function_name}")
    return fn_arn


def ensure_guardrail(bedrock: Any) -> tuple[str, str]:
    cfg = json.loads((AGENTCORE_DIR / "guardrail-config.json").read_text(encoding="utf-8"))
    existing = bedrock.list_guardrails().get("guardrails", [])
    match = next((g for g in existing if g["name"] == cfg["name"]), None)
    if match:
        gid = match["id"]
        print(f"[Bedrock] Using existing Guardrail: {gid}")
        ver_resp = bedrock.create_guardrail_version(guardrailIdentifier=gid, description="Updated Redacted policy")
        return gid, ver_resp["version"]

    resp = bedrock.create_guardrail(**cfg)
    gid = resp["guardrailId"]
    ver_resp = bedrock.create_guardrail_version(guardrailIdentifier=gid, description="Initial Redacted policy")
    print(f"[Bedrock] Created Guardrail: {gid} (version {ver_resp['version']})")
    return gid, ver_resp["version"]


def ensure_cloudwatch(logs: Any, log_group: str, log_stream: str) -> None:
    try:
        logs.create_log_group(logGroupName=log_group)
        print(f"[CloudWatch] Created log group: {log_group}")
    except logs.exceptions.ResourceAlreadyExistsException:
        print(f"[CloudWatch] Using existing log group: {log_group}")
    try:
        logs.create_log_stream(logGroupName=log_group, logStreamName=log_stream)
    except logs.exceptions.ResourceAlreadyExistsException:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy Redacted AWS infrastructure and AgentCore Managed Harness.")
    parser.add_argument("--region", default="us-west-2")
    parser.add_argument("--model-id", default="us.anthropic.claude-sonnet-4-5-20250514-v1:0")
    parser.add_argument("--bucket", default="")
    parser.add_argument("--harness-name", default="redacted_document_assistant")
    args = parser.parse_args()

    try:
        sts = boto3.client("sts", region_name=args.region)
        account_id = sts.get_caller_identity()["Account"]
    except (NoCredentialsError, ClientError) as exc:
        print(f"ERROR: Valid AWS credentials are required before running deploy_aws.py: {exc}")
        return 1

    bucket_name = args.bucket or f"redacted-docs-{account_id}-{args.region}"
    s3 = boto3.client("s3", region_name=args.region)
    iam = boto3.client("iam", region_name=args.region)
    lam = boto3.client("lambda", region_name=args.region)
    bedrock = boto3.client("bedrock", region_name=args.region)
    logs = boto3.client("logs", region_name=args.region)
    ac_ctrl = boto3.client("bedrock-agentcore-control", region_name=args.region)

    ensure_s3_bucket(s3, bucket_name, args.region)
    upload_dataset(bucket_name, args.region)

    cw_group = "/aws/redacted/security-audit"
    cw_stream = "backend-security-events"
    ensure_cloudwatch(logs, cw_group, cw_stream)

    guardrail_id, guardrail_version = ensure_guardrail(bedrock)

    lambda_trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
        }
    )
    hook_lambda_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"arn:aws:logs:{args.region}:{account_id}:log-group:/aws/lambda/redacted-harness-hook:*",
                }
            ],
        }
    )
    hook_role_arn = ensure_iam_role(iam, "RedactedHarnessHookLambdaRole", lambda_trust, "HookLoggingPolicy", hook_lambda_policy)
    hook_arn = ensure_lambda(
        lam,
        "redacted-harness-hook",
        hook_role_arn,
        DEPLOY_DIR / "lambda" / "harness_hook_validator.py",
        "harness_hook_validator.lambda_handler",
        {"LOG_LEVEL": "INFO"},
    )

    retriever_s3_policy = _render_policy(INFRA_DIR / "s3-read-only-policy.json", {"<S3_BUCKET>": bucket_name})
    retriever_role_arn = ensure_iam_role(
        iam, "RedactedDocRetrieverLambdaRole", lambda_trust, "ReadOnlyS3DocumentsPolicy", retriever_s3_policy
    )
    iam.put_role_policy(
        RoleName="RedactedDocRetrieverLambdaRole",
        PolicyName="RetrieverLogsPolicy",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": f"arn:aws:logs:{args.region}:{account_id}:log-group:/aws/lambda/redacted-doc-retriever:*",
                    }
                ],
            }
        ),
    )
    retriever_arn = ensure_lambda(
        lam,
        "redacted-doc-retriever",
        retriever_role_arn,
        DEPLOY_DIR / "lambda" / "s3_document_retriever.py",
        "s3_document_retriever.lambda_handler",
        {"S3_DOCUMENTS_BUCKET": bucket_name},
    )

    harness_trust = (INFRA_DIR / "harness-trust-policy.json").read_text(encoding="utf-8")
    harness_exec_policy = _render_policy(
        INFRA_DIR / "harness-execution-policy.json",
        {"<REGION>": args.region, "<ACCOUNT_ID>": account_id, "<GUARDRAIL_ID>": guardrail_id},
    )
    exec_role_arn = ensure_iam_role(
        iam,
        "RedactedAgentCoreHarnessExecutionRole",
        harness_trust,
        "RedactedHarnessLeastPrivilegePolicy",
        harness_exec_policy,
    )

    bucket_policy = _render_policy(
        INFRA_DIR / "s3-bucket-policy.json",
        {"<S3_BUCKET>": bucket_name, "<ACCOUNT_ID>": account_id},
    )
    s3.put_bucket_policy(Bucket=bucket_name, Policy=bucket_policy)
    print(f"[S3] Applied least-privilege bucket policy to {bucket_name}")

    time.sleep(8)
    harness_cfg = json.loads((AGENTCORE_DIR / "harness-config.json").read_text(encoding="utf-8"))
    hooks_cfg = json.loads(
        _render_policy(AGENTCORE_DIR / "hooks-config.json", {"<REGION>": args.region, "<ACCOUNT_ID>": account_id})
    )
    sys_prompt = [{"text": (AGENTCORE_DIR / "system-instructions.md").read_text(encoding="utf-8")}]
    model_cfg = {
        "bedrockModelConfig": {
            "modelId": args.model_id,
            "apiFormat": "converse_stream",
            "temperature": 0.1,
            "maxTokens": 1200,
            "additionalParams": {
                "guardrailConfig": {
                    "guardrailIdentifier": guardrail_id,
                    "guardrailVersion": guardrail_version,
                    "trace": "enabled_full",
                }
            },
        }
    }
    inline_tools = build_harness_inline_tools()

    existing_harnesses = ac_ctrl.list_harnesses().get("harnesses", [])
    existing = next((h for h in existing_harnesses if h.get("harnessName") == args.harness_name), None)

    if existing:
        harness_id = existing["harnessId"]
        resp = ac_ctrl.update_harness(
            harnessId=harness_id,
            executionRoleArn=exec_role_arn,
            model=model_cfg,
            systemPrompt=sys_prompt,
            tools=inline_tools,
            allowedTools=harness_cfg["allowedTools"],
            hooks=hooks_cfg,
            memory={"optionalValue": harness_cfg["memory"]},
            truncation=harness_cfg["truncation"],
            environment=harness_cfg["environment"],
            maxIterations=harness_cfg["maxIterations"],
            maxTokens=harness_cfg["maxTokens"],
            timeoutSeconds=harness_cfg["timeoutSeconds"],
        )
        harness = resp["harness"]
        print(f"[AgentCore] Updated Managed Harness: {harness['arn']}")
    else:
        resp = ac_ctrl.create_harness(
            harnessName=args.harness_name,
            executionRoleArn=exec_role_arn,
            model=model_cfg,
            systemPrompt=sys_prompt,
            tools=inline_tools,
            allowedTools=harness_cfg["allowedTools"],
            hooks=hooks_cfg,
            memory=harness_cfg["memory"],
            truncation=harness_cfg["truncation"],
            environment=harness_cfg["environment"],
            maxIterations=harness_cfg["maxIterations"],
            maxTokens=harness_cfg["maxTokens"],
            timeoutSeconds=harness_cfg["timeoutSeconds"],
            tags=harness_cfg["tags"],
        )
        harness = resp["harness"]
        harness_id = harness["harnessId"]
        print(f"[AgentCore] Created Managed Harness: {harness['arn']}")

    for _ in range(30):
        cur = ac_ctrl.get_harness(harnessId=harness_id)["harness"]
        status = cur["status"]
        print(f"[AgentCore] Harness status: {status}")
        if status == "READY":
            harness = cur
            break
        if status in ("CREATE_FAILED", "UPDATE_FAILED"):
            print(f"ERROR: Harness failed: {cur.get('failureReason')}")
            return 1
        time.sleep(5)

    outputs = {
        "aws_region": args.region,
        "account_id": account_id,
        "harness_arn": harness["arn"],
        "harness_id": harness["harnessId"],
        "execution_role_arn": exec_role_arn,
        "bedrock_model_id": args.model_id,
        "bedrock_guardrail_id": guardrail_id,
        "bedrock_guardrail_version": guardrail_version,
        "s3_documents_bucket": bucket_name,
        "lambda_hook_arn": hook_arn,
        "lambda_retriever_arn": retriever_arn,
        "cloudwatch_log_group": cw_group,
        "cloudwatch_log_stream": cw_stream,
    }
    (PROJECT_ROOT / "aws_outputs.json").write_text(json.dumps(outputs, indent=2), encoding="utf-8")

    env_content = (
        f"AWS_REGION={args.region}\n"
        f"AGENTCORE_HARNESS_ARN={harness['arn']}\n"
        f"AGENTCORE_HARNESS_ID={harness['harnessId']}\n"
        f"AGENTCORE_HARNESS_QUALIFIER=DEFAULT\n"
        f"AGENTCORE_EXECUTION_ROLE_ARN={exec_role_arn}\n"
        f"BEDROCK_MODEL_ID={args.model_id}\n"
        f"BEDROCK_GUARDRAIL_ID={guardrail_id}\n"
        f"BEDROCK_GUARDRAIL_VERSION={guardrail_version}\n"
        f"S3_DOCUMENTS_BUCKET={bucket_name}\n"
        f"S3_DOCUMENTS_PREFIX=documents/\n"
        f"DOCUMENT_SOURCE_MODE=s3\n"
        f"LAMBDA_RETRIEVER_ARN={retriever_arn}\n"
        f"LAMBDA_HOOK_ARN={hook_arn}\n"
        f"CLOUDWATCH_LOG_GROUP={cw_group}\n"
        f"CLOUDWATCH_LOG_STREAM={cw_stream}\n"
        f"REDACTED_AUTH_SECRET=replace-with-strong-random-32-byte-secret\n"
    )
    (PROJECT_ROOT / ".env").write_text(env_content, encoding="utf-8")
    print("\nDeployment completed. Generated .env and aws_outputs.json.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
