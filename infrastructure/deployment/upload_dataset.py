"""Upload synthetic enterprise documents to Amazon S3 under least-privilege prefixes."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_ROOT / "data" / "documents"


def upload_dataset(
    bucket_name: str,
    region: str = "ap-southeast-2",
    session: Optional[boto3.Session] = None,
) -> None:
    sess = session or boto3.Session(region_name=region)
    s3: Any = sess.client("s3", region_name=region)
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
    parser = argparse.ArgumentParser(description="Upload synthetic documents dataset to Amazon S3.")
    parser.add_argument("bucket", help="Target S3 bucket name")
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "ap-southeast-2"))
    parser.add_argument("--profile", default=os.environ.get("AWS_PROFILE", "redacted"))
    args = parser.parse_args()

    try:
        sess_kwargs: dict[str, str] = {"region_name": args.region}
        if args.profile:
            sess_kwargs["profile_name"] = args.profile
        session = boto3.Session(**sess_kwargs)
        upload_dataset(args.bucket, args.region, session=session)
    except (NoCredentialsError, ProfileNotFound, ClientError) as exc:
        print(f"AWS S3 error: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
