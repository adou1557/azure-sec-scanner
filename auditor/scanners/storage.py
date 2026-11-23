from typing import List
from azure.mgmt.storage import StorageManagementClient
from azure.core.exceptions import HttpResponseError
from auditor.models import Finding
from auditor.auth import get_azure_credential

class StorageScanner:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = get_azure_credential()
        self.client = StorageManagementClient(self.credential, self.subscription_id)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []
        try:
            accounts = self.client.storage_accounts.list()
            for account in accounts:
                name = account.name

                # CIS 9.2.1.1 - Accès réseau public désactivé
                if (account.public_network_access or "").lower() != "disabled":
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 9.2.1.1",
                        severity="HIGH",
                        issue=f"Accès réseau public actif ({account.public_network_access}). Attendu : 'Disabled'."
                    ))

                # CIS 9.2.1.2 - Action réseau par défaut à Deny
                if account.network_rule_set:
                    default_action = getattr(account.network_rule_set, "default_action", None)
                    if default_action and str(default_action).lower() != "deny":
                        findings.append(Finding(
                            resource=name,
                            cis_id="CIS 9.2.1.2",
                            severity="HIGH",
                            issue=f"Règle par défaut du pare-feu à '{default_action}'. Attendu : 'Deny'."
                        ))

                # CIS 9.2.3 - Transfert sécurisé HTTPS
                if not account.enable_https_traffic_only:
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 9.2.3",
                        severity="HIGH",
                        issue="Transfert non chiffré (HTTP) autorisé."
                    ))

                # CIS 9.2.4 - TLS 1.2 minimum
                if account.minimum_tls_version != "TLS1_2":
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 9.2.4",
                        severity="MEDIUM",
                        issue=f"Version TLS obsolète ({account.minimum_tls_version}). TLS 1.2 requis."
                    ))

                # CIS 9.2.5 - Accès anonyme/public aux blobs
                if account.allow_blob_public_access is not False:
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 9.2.5",
                        severity="CRITICAL",
                        issue=f"Accès public aux blobs non verrouillé ({account.allow_blob_public_access})."
                    ))

        except HttpResponseError as err:
            print(f"[ERREUR] Échec de lecture Storage ARM : {err.message}")
            raise err

        return findings
