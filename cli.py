import os
import sys
import argparse
from scanners.storage import StorageScanner
from reporters.console import print_console_report

def main():
    parser = argparse.ArgumentParser(description="Scanner d'audit de sécurité Azure (CIS Benchmark v7.0.0)")
    parser.add_argument(
        "--subscription-id",
        default=os.environ.get("AZURE_SUBSCRIPTION_ID"),
        help="ID de la souscription Azure à auditer (ou via variable AZURE_SUBSCRIPTION_ID)"
    )
    args = parser.parse_args()

    if not args.subscription_id:
        print("Erreur : L'ID de souscription est requis (argument --subscription-id ou export AZURE_SUBSCRIPTION_ID).")
        sys.exit(1)

    print(f"[*] Démarrage de l'audit sur la souscription : {args.subscription_id}")

    # 1. Exécution du scanner Storage
    storage_scanner = StorageScanner(args.subscription_id)
    findings = storage_scanner.scan()

    # 2. Restitution
    print_console_report(findings)

if __name__ == "__main__":
    main()