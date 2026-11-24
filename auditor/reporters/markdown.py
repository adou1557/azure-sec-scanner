from datetime import datetime
from pathlib import Path
from typing import List
from auditor.models import Finding

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def generate_markdown_report(findings: List[Finding], output_path: str = "audit_report.md") -> str:
    """
    Génère un rapport d'audit au format Markdown consolidant les anomalies
    (Storage, Réseau, Key Vault) et l'écrit dans output_path.
    """
    # 1. Tri hiérarchique par sévérité (CRITICAL -> HIGH -> MEDIUM -> LOW)
    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # 2. Calcul des métriques de conformité
    total = len(sorted_findings)
    crit = sum(1 for f in sorted_findings if f.severity == "CRITICAL")
    high = sum(1 for f in sorted_findings if f.severity == "HIGH")
    med = sum(1 for f in sorted_findings if f.severity == "MEDIUM")
    low = sum(1 for f in sorted_findings if f.severity == "LOW")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 3. Construction du document Markdown
    lines = [
        "# Rapport d'Audit de Sécurité Azure",
        "",
        f"- **Date du scan :** `{now}`",
        f"- **Total des non-conformités :** `{total}` (🚨 CRITICAL: {crit} | ⚠️ HIGH: {high} | 🟡 MEDIUM: {med} | ℹ️ LOW: {low})",
        "",
    ]

    if not sorted_findings:
        lines.append("✅ **Aucune anomalie détectée.** L'environnement analysé est 100% conforme au baseline CIS v7.0.0.")
    else:
        lines.extend([
            "| Sévérité | Contrôle CIS | Ressource | Problème détecté |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for f in sorted_findings:
            # Sécurisation des séparateurs pour éviter de casser le rendu du tableau Markdown
            severity = str(f.severity).replace("|", "\\|")
            cis_id = str(f.cis_id).replace("|", "\\|")
            resource = str(f.resource).replace("|", "\\|").replace("\n", " ")
            issue = str(f.issue).replace("|", "\\|").replace("\n", " ")

            lines.append(f"| **{severity}** | `{cis_id}` | `{resource}` | {issue} |")

    lines.append("")  # Ligne vide finale

    # 4. Écriture sécurisée avec création automatique des répertoires parents
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines), encoding="utf-8")

    return str(out)