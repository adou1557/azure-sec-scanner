from typing import List
from auditor.models import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def print_console_report(findings: List[Finding]) -> None:
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    print(f"\n{'='*70}")
    print(f" RAPPORT D'AUDIT DE SÉCURITÉ AZURE : {len(sorted_findings)} ANOMALIES TROUVÉES")
    print(f"{'='*70}")

    if not sorted_findings:
        print("[+] Aucune vulnérabilité détectée. Environnement conforme !")
        return

    for f in sorted_findings:
        print(f"[{f.severity:<8}] {f.cis_id:<12} | {f.resource:<25} -> {f.issue}")
    print(f"{'='*70}\n")