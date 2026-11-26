"""Read-only AWS Lambda S3 document retriever invoked by the authenticated backend (R01, R02)."""

from __future__ import annotations

import json
import os
from typing import Any, Dict

import boto3

s3_client = boto3.client("s3")
DEFAULT_BUCKET = os.environ.get("S3_DOCUMENTS_BUCKET", "")


def lambda_handler(event: Dict[str, Any], _context: Any) -> Dict[str, Any]:
    bucket = str(event.get("bucket") or DEFAULT_BUCKET).strip()
    key = str(event.get("key") or "").strip()
    doc_id = str(event.get("doc_id") or "").strip()

    if not bucket or not key or not key.startswith("documents/") or ".." in key:
        return {"statusCode": 400, "error": "R09: Invalid S3 document reference."}

    # Defense-in-depth: never return restricted raw files via general retriever
    if key.startswith("documents/restricted/") or doc_id in {"DOC-PAYROLL-2026", "DOC-EXEC-BOARD-2026"}:
        return {"statusCode": 403, "error": "R03: Restricted payroll/executive objects are blocked at the retriever."}

    obj = s3_client.get_object(Bucket=bucket, Key=key)
    document = json.loads(obj["Body"].read().decode("utf-8"))
    return {"statusCode": 200, "document": document}
