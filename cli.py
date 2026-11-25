import os
import sys
import argparse

# Si ton dossier s'appelle auditor/, adapte les imports (ex: from auditor.scanners...)
from auditor.scanners.storage import StorageScanner
from auditor.scanners.network import NetworkScanner
from auditor.scanners.keyvault import KeyVaultScanner
from auditor.reporters.console import print_console_report
from auditor.reporters.markdown import generate_markdown_report


def main():
    parser = argparse.ArgumentParser(
        description="Scanner d'audit de sécurité Azure (CIS Benchmark v7.0.0)"
    )
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="ID de la souscription Azure à auditer (ou via variable AZURE_SUBSCRIPTION_ID)",
    )
    # Déclaration de l'argument de sortie Markdown
    parser.add_argument(
        "--output",
        "-o",
        help="Chemin du fichier Markdown pour exporter le rapport (ex: reports/audit.md)",
        default=None,
    )
    args = parser.parse_args()

    if not args.subscription_id:
        print("Erreur : L'ID de souscription est requis (argument --subscription-id ou export AZURE_SUBSCRIPTION_ID).")
        sys.exit(1)

    print(f"[*] Démarrage de l'audit sur la souscription : {args.subscription_id}")

    # Initialisation de la liste consolidée
    all_findings = []

    # Définition des modules de scan
    scanners = [
        ("Storage Accounts", StorageScanner(args.subscription_id)),
        ("Network Security Groups", NetworkScanner(args.subscription_id)),
        ("Key Vaults", KeyVaultScanner(args.subscription_id)),
    ]

    # Exécution séquentielle de chaque scanner
    for name, scanner in scanners:
        print(f"[*] Analyse en cours : {name}...")
        findings = scanner.scan()
        all_findings.extend(findings)
        print(f"    -> {len(findings)} anomalie(s) détectée(s)")

    # 1. Restitution console (toujours exécutée)
    print_console_report(all_findings)

    # 2. Export Markdown (uniquement si demandé en argument CLI)
    if args.output:
        report_path = generate_markdown_report(all_findings, args.output)
        print(f"[+] Rapport Markdown généré avec succès dans : {report_path}")


if __name__ == "__main__":
    main()