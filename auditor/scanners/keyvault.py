from typing import List
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.core.exceptions import HttpResponseError
from auditor.models import Finding
from auditor.auth import get_azure_credential


class KeyVaultScanner:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = get_azure_credential()
        self.client = KeyVaultManagementClient(self.credential, self.subscription_id)

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        try:
            # Énumère tous les coffres de la souscription
            vaults = self.client.vaults.list_by_subscription()

            for vault in vaults:
                name = vault.name
                props = vault.properties

                # Sécurité : certains états partiels peuvent renvoyer properties à None
                if not props:
                    continue

                # CIS 8.3.8 - Protection contre la purge (Purge Protection)
                if props.enable_purge_protection is not True:
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 8.3.8",
                        severity="HIGH",
                        issue=(
                            f"La protection contre la purge est désactivée "
                            f"(enable_purge_protection = {props.enable_purge_protection}). "
                            "Attendu : 'True'."
                        )
                    ))

                # CIS 8.3.9 - Autorisation via Azure RBAC (au lieu des Access Policies legacy)
                if props.enable_rbac_authorization is not True:
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 8.3.9",
                        severity="MEDIUM",
                        issue=(
                            f"Le contrôle d'accès RBAC est désactivé "
                            f"(enable_rbac_authorization = {props.enable_rbac_authorization}). "
                            "Attendu : 'True'."
                        )
                    ))

                # CIS 8.3.11 - Désactivation de l'accès réseau public
                public_access = (getattr(props, "public_network_access", "") or "").lower()
                if public_access != "disabled":
                    findings.append(Finding(
                        resource=name,
                        cis_id="CIS 8.3.11",
                        severity="HIGH",
                        issue=(
                            f"L'accès réseau public est actif ('{props.public_network_access}'). "
                            "Attendu : 'Disabled'."
                        )
                    ))

                # CIS 8.3.10 - Pare-feu réseau par défaut à Deny (si l'accès public n'est pas coupé)
                if public_access != "disabled" and props.network_acls:
                    default_action = (getattr(props.network_acls, "default_action", "") or "").lower()
                    if default_action != "deny":
                        findings.append(Finding(
                            resource=name,
                            cis_id="CIS 8.3.10",
                            severity="HIGH",
                            issue=(
                                f"L'action réseau par défaut du coffre est '{props.network_acls.default_action}'. "
                                "Attendu : 'Deny'."
                            )
                        ))

        except HttpResponseError as e:
            print(f"[ERREUR ARM] Scanner Key Vault : {e.message}")
            raise e

        return findings