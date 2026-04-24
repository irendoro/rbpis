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

# Бан-лист компонентов (package_name: [min_version, reason])
BANNED_COMPONENTS = {
    "python-jose": {
        "min_version": "3.4.0",
        "reason": "CVE-2024-26308 - vulnerable to signature bypass"
    },
    "python-multipart": {
        "min_version": "0.0.22",
        "reason": "CVE-2024-27306 - DoS vulnerability in multipart parser"
    },
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


def load_sca_findings(path: Path) -> tuple[list[dict], list[dict]]:
    """
    Загружает SCA отчёт Trivy и возвращает:
    - vulnerability_findings: критические и высокие уязвимости
    - banned_findings: бан-лист компонентов с недопустимыми версиями
    """
    if not path.exists():
        print(f"[WARN] SCA report not found: {path}")
        return [], []
    
    data = json.loads(path.read_text(encoding="utf-8"))
    vulnerability_findings = []
    banned_findings = []
    
    # Парсим уязвимости из результатов
    for result in data.get("Results", []):
        vulnerabilities = result.get("Vulnerabilities", [])
        
        for vuln in vulnerabilities:
            severity = vuln.get("Severity", "LOW").upper()
            severity_level = SEVERITY_ORDER.get(severity, 0)
            
            # Берем только HIGH и CRITICAL для блокировки
            if severity_level >= SEVERITY_ORDER["HIGH"]:
                vulnerability_findings.append({
                    "tool": "trivy",
                    "severity": severity,
                    "severity_level": severity_level,
                    "test_id": vuln.get("VulnerabilityID", "UNKNOWN"),
                    "file": f"{result.get('Target', 'unknown')} ({vuln.get('PkgName', 'unknown')})",
                    "line": f"version: {vuln.get('InstalledVersion', '?')}",
                    "message": (
                        f"{vuln.get('Title', vuln.get('Description', 'No description'))} "
                        f"[Fixed in: {vuln.get('FixedVersion', 'N/A')}]"
                    ),
                })
        
        # Парсим пакеты для проверки бан-листа
        packages = result.get("Packages", [])
        for pkg in packages:
            pkg_name = pkg.get("Name", "")
            pkg_version = pkg.get("Version", "")
            
            if pkg_name in BANNED_COMPONENTS:
                banned_info = BANNED_COMPONENTS[pkg_name]
                min_version = banned_info["min_version"]
                
                # Проверка версии
                if not is_version_compatible(pkg_version, min_version):
                    banned_findings.append({
                        "tool": "trivy-banned",
                        "severity": "CRITICAL",
                        "severity_level": SEVERITY_ORDER["CRITICAL"],
                        "test_id": "BANNED_COMPONENT",
                        "file": result.get("Target", "unknown"),
                        "line": f"{pkg_name} {pkg_version}",
                        "message": (
                            f"Banned component: {pkg_name} {pkg_version} "
                            f"(required >= {min_version}). {banned_info['reason']}"
                        ),
                    })
    
    print(f"[INFO] SCA: Found {len(vulnerability_findings)} HIGH/CRITICAL vulnerabilities")
    print(f"[INFO] SCA: Found {len(banned_findings)} banned components")
    
    return vulnerability_findings, banned_findings


def is_version_compatible(current_version: str, min_version: str) -> bool:
    """Сравнивает версии, возвращает True если current >= min"""
    def normalize(v):
        # Удаляем префиксы v, V и суффиксы типа -rc1
        v = re.sub(r'^[vV]', '', v)
        v = re.sub(r'[-_].*$', '', v)
        parts = v.split('.')
        # Дополняем до 3 частей нулями
        while len(parts) < 3:
            parts.append('0')
        return tuple(int(p) for p in parts[:3] if p.isdigit())
    
    try:
        current_norm = normalize(current_version)
        min_norm = normalize(min_version)
        return current_norm >= min_norm
    except (ValueError, AttributeError):
        # Если не удалось распарсить, считаем несовместимой
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Security Gate for SAST, SCA and DAST reports")
    parser.add_argument("--bandit", help="Path to Bandit JSON report")
    parser.add_argument("--zap-passive", help="Path to ZAP passive scan HTML report")
    parser.add_argument("--zap-active", help="Path to ZAP active scan HTML report")
    parser.add_argument("--sca", help="Path to Trivy SCA JSON report")
    parser.add_argument(
        "--threshold",
        default="high",
        choices=["low", "medium", "high", "critical"],
        help="Fail pipeline if severity is equal or above this level",
    )
    args = parser.parse_args()

    threshold = SEVERITY_ORDER[args.threshold.upper()]
    all_findings = []
    banned_findings = []

    # Загружаем Bandit
    if args.bandit:
        all_findings.extend(load_bandit_findings(Path(args.bandit)))

    # Загружаем ZAP отчёты
    if args.zap_passive:
        all_findings.extend(load_zap_findings_from_html(Path(args.zap_passive)))
    if args.zap_active:
        all_findings.extend(load_zap_findings_from_html(Path(args.zap_active)))

    # Загружаем SCA (Trivy)
    if args.sca:
        vuln_findings, banned = load_sca_findings(Path(args.sca))
        all_findings.extend(vuln_findings)
        banned_findings.extend(banned)

    # Фильтруем уязвимости выше порога
    blocked = [f for f in all_findings if f["severity_level"] >= threshold]
    
    # Добавляем бан-лист компонентов (всегда блокируют)
    if banned_findings:
        blocked.extend(banned_findings)

    print(f"\n{'='*60}")
    print(f"SECURITY GATE SUMMARY")
    print(f"{'='*60}")
    print(f"Total findings: {len(all_findings)}")
    print(f"Threshold: {args.threshold.upper()}")
    print(f"Blocked (severity >= {args.threshold.upper()}): {len([f for f in all_findings if f['severity_level'] >= threshold])}")
    print(f"Banned components: {len(banned_findings)}")
    print(f"Total blocked issues: {len(blocked)}")

    if blocked:
        print(f"\n{'='*60}")
        print("BLOCKED FINDINGS:")
        print(f"{'='*60}")
        
        # Группируем по типу инструмента
        bandit_issues = [f for f in blocked if f['tool'] == 'bandit']
        trivy_issues = [f for f in blocked if f['tool'] == 'trivy']
        banned_issues = [f for f in blocked if f['tool'] == 'trivy-banned']
        zap_issues = [f for f in blocked if f['tool'] == 'zap']
        
        if bandit_issues:
            print(f"\n🔍 SAST (Bandit) Issues:")
            for finding in bandit_issues:
                print(f"\n  🔴 [{finding['severity']}] {finding['test_id']}")
                print(f"     File: {finding['file']}:{finding['line']}")
                print(f"     Message: {finding['message']}")
        
        if trivy_issues:
            print(f"\n📦 SCA (Trivy) Vulnerabilities:")
            for finding in trivy_issues:
                print(f"\n  🔴 [{finding['severity']}] {finding['test_id']}")
                print(f"     Package: {finding['file']}")
                print(f"     Message: {finding['message']}")
        
        if banned_issues:
            print(f"\n🚫 Banned Components:")
            for finding in banned_issues:
                print(f"\n  🔴 {finding['message']}")
                print(f"     Location: {finding['file']}")
        
        if zap_issues:
            print(f"\n🌐 DAST (ZAP) Issues:")
            for finding in zap_issues:
                print(f"\n  🔴 [{finding['severity']}] {finding['test_id']}")
                print(f"     Message: {finding['message']}")
        
        print(f"\n{'='*60}")
        print("Security Gate decision: BLOCK ❌")
        print(f"{'='*60}")
        
        # Выводим рекомендации по фикса
        print("\n📋 RECOMMENDATIONS:")
        if banned_issues:
            print("  • Update banned components to secure versions:")
            for comp in BANNED_COMPONENTS:
                print(f"    - {comp} >= {BANNED_COMPONENTS[comp]['min_version']}")
        if trivy_issues:
            print("  • Update vulnerable dependencies to patched versions")
            print("  • Run: pip list --outdated | grep <package_name>")
        if bandit_issues:
            print("  • Fix Bandit issues in your Python code")
            print("  • Run locally: bandit -r . -ll")
        if zap_issues:
            print("  • Review ZAP findings and implement security fixes")
            print("  • Check: https://www.zaproxy.org/docs/alerts/")
        
        return 1

    print(f"\n{'='*60}")
    print("Security Gate decision: PASS ✅")
    print(f"{'='*60}")
    return 0


if __name__ == "__main__":
    sys.exit(main())