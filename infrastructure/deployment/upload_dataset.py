"""Upload synthetic enterprise documents to Amazon S3 under least-privilege prefixes."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "documents"


def upload_dataset(bucket_name: str, region: str) -> None:
    s3 = boto3.client("s3", region_name=region)
    manifest = json.loads((DATA_DIR / "manifest.json").read_text(encoding="utf-8"))

    # Upload manifest
    s3.put_object(
        Bucket=bucket_name,
        Key="documents/manifest.json",
        Body=json.dumps(manifest, indent=2).encode("utf-8"),
        ContentType="application/json",
    )
    print(f"Uploaded s3://{bucket_name}/documents/manifest.json")

    for doc_meta in manifest.get("documents", []):
        doc_id = doc_meta["doc_id"]
        s3_key = doc_meta["s3_key"]
        doc_file = DATA_DIR / f"{doc_id}.json"
        if not doc_file.exists():
            raise FileNotFoundError(f"Missing synthetic document file: {doc_file}")
        s3.put_object(
            Bucket=bucket_name,
            Key=s3_key,
            Body=doc_file.read_bytes(),
            ContentType="application/json",
        )
        print(f"Uploaded s3://{bucket_name}/{s3_key}")


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: python scripts/upload_dataset.py <s3-bucket-name> [aws-region]")
        return 1
    bucket = sys.argv[1]
    region = sys.argv[2] if len(sys.argv) > 2 else "us-west-2"
    try:
        upload_dataset(bucket, region)
    except ClientError as exc:
        print(f"AWS S3 error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
