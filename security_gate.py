import argparse
import json
import sys
from pathlib import Path

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def load_bandit_findings(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for item in data.get("results", []):
        findings.append(
            {
                "tool": "bandit",
                "severity": item.get("issue_severity", "LOW").upper(),
                "test_id": item.get("test_id", "UNKNOWN"),
                "file": item.get("filename", "unknown"),
                "line": item.get("line_number", "?"),
                "message": item.get("issue_text", ""),
            }
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Gate for Bandit JSON report")
    parser.add_argument("--bandit", required=True, help="Path to Bandit JSON report")
    parser.add_argument(
        "--threshold",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Fail pipeline if severity is equal or above this level",
    )
    args = parser.parse_args()

    threshold = SEVERITY_ORDER[args.threshold.upper()]
    findings = load_bandit_findings(Path(args.bandit))
    blocked = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]

    print(f"Total findings: {len(findings)}")
    print(f"Threshold: {args.threshold.upper()}")

    if blocked:
        print("Security Gate decision: BLOCK")
        for finding in blocked:
            print(
                f"- [{finding['severity']}] {finding['tool']} {finding['test_id']} "
                f"{finding['file']}:{finding['line']} - {finding['message']}"
            )
        return 1

    print("Security Gate decision: PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
