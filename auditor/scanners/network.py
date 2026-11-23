from typing import List
from azure.mgmt.network import NetworkManagementClient
from azure.core.exceptions import HttpResponseError
from auditor.models import Finding
from auditor.auth import get_azure_credential


class NetworkScanner:
    def __init__(self, subscription_id: str):
        self.subscription_id = subscription_id
        self.credential = get_azure_credential()
        self.client = NetworkManagementClient(self.credential, self.subscription_id)

    @staticmethod
    def is_internet_source(rule) -> bool:
        """Normalise et vérifie si la source autorise le trafic depuis tout Internet."""
        sources = set()
        # Normalisation chaîne unique ou liste d'adresses
        if rule.source_address_prefix:
            sources.add(rule.source_address_prefix.strip().lower())
        if rule.source_address_prefixes:
            for s in rule.source_address_prefixes:
                sources.add(s.strip().lower())

        patterns_internet = {"*", "0.0.0.0/0", "internet", "<internet>"}
        return bool(sources.intersection(patterns_internet))

    @staticmethod
    def port_is_exposed(target_port: int, rule) -> bool:
        """Vérifie si un port spécifique est inclus dans la plage ou la liste de destination."""
        plages = []
        if rule.destination_port_range:
            plages.append(rule.destination_port_range.strip())
        if rule.destination_port_ranges:
            plages.extend([p.strip() for p in rule.destination_port_ranges])

        for p in plages:
            if p == "*":
                return True
            if "-" in p:
                try:
                    debut, fin = map(int, p.split("-"))
                    if debut <= target_port <= fin:
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if int(p) == target_port:
                        return True
                except ValueError:
                    continue
        return False

    def scan(self) -> List[Finding]:
        findings: List[Finding] = []

        try:
            # list_all() énumère l'ensemble des NSG sans exiger de Resource Group préalable
            network_security_groups = self.client.network_security_groups.list_all()

            for nsg in network_security_groups:
                nsg_name = nsg.name
                # Sécurité : si un NSG n'a pas de règles custom, l'API renvoie None
                nsg_rules = nsg.security_rules or []

                for nsg_rule in nsg_rules:
                    is_inbound = (nsg_rule.direction or "").lower() == "inbound"
                    is_allow = (nsg_rule.access or "").lower() == "allow"

                    if is_inbound and is_allow and self.is_internet_source(nsg_rule):
                        source_affichee = (
                                nsg_rule.source_address_prefix
                                or nsg_rule.source_address_prefixes
                        )

                        # CIS 7.1.5 - Port SSH (22) ouvert à Internet
                        if self.port_is_exposed(22, nsg_rule):
                            findings.append(Finding(
                                resource=f"{nsg_name}/{nsg_rule.name}",
                                cis_id="CIS 7.1.5",
                                severity="CRITICAL",  # CIS classe l'accès direct aux ports d'administration en CRITICAL
                                issue=(
                                    f"Le port SSH (22) est ouvert sur Internet via la règle '{nsg_rule.name}'. "
                                    f"Source configurée : {source_affichee}."
                                )
                            ))

                        # CIS 7.1.1 - Port RDP (3389) ouvert à Internet
                        if self.port_is_exposed(3389, nsg_rule):
                            findings.append(Finding(
                                resource=f"{nsg_name}/{nsg_rule.name}",
                                cis_id="CIS 7.1.1",
                                severity="CRITICAL",
                                issue=(
                                    f"Le port RDP (3389) est ouvert sur Internet via la règle '{nsg_rule.name}'. "
                                    f"Source configurée : {source_affichee}."
                                )
                            ))

        except HttpResponseError as e:
            # Capture des erreurs de permission RBAC (ex. 403 Reader manquant) ou de réseau ARM
            print(f"[ERREUR ARM] Scanner Réseau : {e.message}")
            raise e

        return findings