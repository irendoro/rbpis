import argparse
import json
import sys
import re
from pathlib import Path

SEVERITY_ORDER = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def load_bandit_findings(path: Path) -> list[dict]:
    if not path.exists():
        print(f"[WARN] Bandit report not found: {path}")
        return []
    
    data = json.loads(path.read_text(encoding="utf-8"))
    findings = []
    for item in data.get("results", []):
        severity = item.get("issue_severity", "LOW").upper()
        findings.append({
            "tool": "bandit",
            "severity": severity,
            "severity_level": SEVERITY_ORDER.get(severity, 0),
            "test_id": item.get("test_id", "UNKNOWN"),
            "file": item.get("filename", "unknown"),
            "line": item.get("line_number", "?"),
            "message": item.get("issue_text", ""),
        })
    return findings


def load_zap_findings_from_html(path: Path) -> list[dict]:
    """Парсит HTML отчёт ZAP, находит только HIGH и CRITICAL"""
    if not path.exists():
        print(f"[WARN] ZAP report not found: {path}")
        return []
    
    content = path.read_text(encoding="utf-8")
    findings = []
    
    # Ищем HIGH и CRITICAL уязвимости в HTML таблице ZAP
    pattern = r'<tr[^>]*>\s*<td[^>]*>(HIGH|CRITICAL)[^<]*<\/td>\s*<td[^>]*>([^<]+)<\/td>'
    matches = re.findall(pattern, content, re.IGNORECASE)
    
    for severity, name in matches:
        severity_upper = severity.upper()
        findings.append({
            "tool": "zap",
            "severity": severity_upper,
            "severity_level": SEVERITY_ORDER.get(severity_upper, 0),
            "test_id": "ZAP_ALERT",
            "file": path.name,
            "line": "?",
            "message": name.strip(),
        })
    
    print(f"[INFO] Found {len(findings)} HIGH/CRITICAL issues in {path.name}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Gate for Bandit and ZAP reports")
    parser.add_argument("--bandit", help="Path to Bandit JSON report")
    parser.add_argument("--zap-passive", help="Path to ZAP passive scan HTML report")
    parser.add_argument("--zap-active", help="Path to ZAP active scan HTML report")
    parser.add_argument(
        "--threshold",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Fail pipeline if severity is equal or above this level",
    )
    args = parser.parse_args()

    threshold = SEVERITY_ORDER[args.threshold.upper()]
    all_findings = []

    # Загружаем Bandit
    if args.bandit:
        all_findings.extend(load_bandit_findings(Path(args.bandit)))

    # Загружаем ZAP отчёты
    if args.zap_passive:
        all_findings.extend(load_zap_findings_from_html(Path(args.zap_passive)))
    if args.zap_active:
        all_findings.extend(load_zap_findings_from_html(Path(args.zap_active)))

    # Фильтруем уязвимости выше порога
    blocked = [f for f in all_findings if f["severity_level"] >= threshold]

    print(f"\n{'='*60}")
    print(f"SECURITY GATE SUMMARY")
    print(f"{'='*60}")
    print(f"Total findings: {len(all_findings)}")
    print(f"Threshold: {args.threshold.upper()}")
    print(f"Blocked (severity >= {args.threshold.upper()}): {len(blocked)}")

    if blocked:
        print(f"\n{'='*60}")
        print("BLOCKED FINDINGS:")
        print(f"{'='*60}")
        for finding in blocked:
            print(f"\n🔴 [{finding['severity']}] {finding['tool'].upper()}")
            print(f"   Test: {finding['test_id']}")
            print(f"   Location: {finding['file']}:{finding['line']}")
            print(f"   Message: {finding['message']}")
        
        print(f"\n{'='*60}")
        print("Security Gate decision: BLOCK ❌")
        print(f"{'='*60}")
        return 1

    print(f"\n{'='*60}")
    print("Security Gate decision: PASS ✅")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())