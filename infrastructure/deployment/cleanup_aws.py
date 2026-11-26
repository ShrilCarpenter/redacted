"""Tear down all Redacted AWS resources to stop ongoing cloud charges.

Usage (Windows PowerShell):
  .\\backend\\.venv\\Scripts\\python.exe infrastructure\\deployment\\cleanup_aws.py --region ap-southeast-2 --profile redacted
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    parser = argparse.ArgumentParser(description="Clean up all AWS resources created by Redacted.")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-southeast-2"))
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "redacted"))
    args = parser.parse_args()

    outputs_path = PROJECT_ROOT / "aws_outputs.json"
    outputs = json.loads(outputs_path.read_text(encoding="utf-8")) if outputs_path.exists() else {}
    region = outputs.get("aws_region", args.region)
    profile = outputs.get("aws_profile", args.profile)

    try:
        sess_kwargs: dict[str, str] = {"region_name": region}
        if profile:
            sess_kwargs["profile_name"] = profile
        session = boto3.Session(**sess_kwargs)
        sts = session.client("sts", region_name=region)
        account_id = sts.get_caller_identity()["Account"]
    except (NoCredentialsError, ProfileNotFound, ClientError) as exc:
        print(f"ERROR: AWS credentials unavailable: {exc}")
        return 1

    ac_ctrl = session.client("bedrock-agentcore-control", region_name=region)
    bedrock = session.client("bedrock", region_name=region)
    lam = session.client("lambda", region_name=region)
    iam = session.client("iam", region_name=region)
    s3 = session.client("s3", region_name=region)
    logs = session.client("logs", region_name=region)

    harness_id = outputs.get("harness_id")
    if harness_id:
        try:
            ac_ctrl.delete_harness(harnessId=harness_id, deleteManagedMemory=True)
            print(f"[AgentCore] Deleted Harness and managed memory: {harness_id}")
        except ClientError as exc:
            print(f"[AgentCore] Skip delete harness: {exc}")

    guardrail_id = outputs.get("bedrock_guardrail_id")
    if guardrail_id:
        try:
            bedrock.delete_guardrail(guardrailIdentifier=guardrail_id)
            print(f"[Bedrock] Deleted Guardrail: {guardrail_id}")
        except ClientError as exc:
            print(f"[Bedrock] Skip delete guardrail: {exc}")

    for fn_name in ("redacted-harness-hook", "redacted-doc-retriever"):
        try:
            lam.delete_function(FunctionName=fn_name)
            print(f"[Lambda] Deleted function: {fn_name}")
        except ClientError as exc:
            print(f"[Lambda] Skip {fn_name}: {exc}")

    for role_name in (
        "RedactedAgentCoreHarnessExecutionRole",
        "RedactedHarnessHookLambdaRole",
        "RedactedDocRetrieverLambdaRole",
    ):
        try:
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            iam.delete_role(RoleName=role_name)
            print(f"[IAM] Deleted role: {role_name}")
        except ClientError as exc:
            print(f"[IAM] Skip {role_name}: {exc}")

    bucket = outputs.get("s3_documents_bucket") or f"redacted-docs-{account_id}-{region}"
    try:
        s3.delete_bucket_policy(Bucket=bucket)
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [
                {"Key": x["Key"], "VersionId": x["VersionId"]}
                for x in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=bucket)
        print(f"[S3] Emptied and deleted bucket: {bucket}")
    except ClientError as exc:
        print(f"[S3] Skip bucket cleanup: {exc}")

    try:
        logs.delete_log_group(logGroupName=outputs.get("cloudwatch_log_group", "/aws/redacted/security-audit"))
        print("[CloudWatch] Deleted audit log group")
    except ClientError as exc:
        print(f"[CloudWatch] Skip log group cleanup: {exc}")

    print("\nCleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
