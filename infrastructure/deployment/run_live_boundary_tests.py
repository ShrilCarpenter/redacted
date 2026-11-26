"""CLI runner to execute the Boundary Tests against the live AgentCore Managed Harness and export JSON."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from agent import run_boundary_tests  # noqa: E402
from authorization import USER_DIRECTORY  # noqa: E402


def main() -> int:
    user = USER_DIRECTORY["claire.vance"]
    report = run_boundary_tests(user=user)
    out_file = PROJECT_ROOT / "boundary_test_report.json"
    out_file.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    print(f"AWS Connected: {report.aws_connected}")
    print(f"Summary: {report.summary}")
    print(f"Exported report to: {out_file}")
    return 0 if report.aws_connected and report.summary.get("fail", 0) == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
