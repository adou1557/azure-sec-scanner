# azure-sec-scanner

Azure Security Audit Scanner is a command-line tool built with Python and the Azure SDK. Designed to connect to an Azure subscription with read-only permissions, it automatically audits critical security configurations—such as accounts without MFA, publicly exposed Storage Accounts, overly permissive NSG rules, and Key Vault secrets without expiration dates—and generates a clean, actionable audit report in Console, Markdown, or HTML formats.

---

## 1. Architecture & Project Layout

```text
azure-sec-scanner/
├── auditor/
│   ├── __init__.py
│   ├── auth.py              # Azure authentication (DefaultAzureCredential)
│   ├── models.py            # Data models & Finding dataclass
│   ├── reporters/           # Audit report generators
│   │   ├── __init__.py
│   │   ├── console.py       # Terminal output sorted by severity
│   │   └── markdown.py      # Markdown report exporter
│   └── scanners/            # Auditing modules per Azure service
│       ├── __init__.py
│       ├── storage.py       # Storage Accounts audit (CIS Section 9.2)
│       ├── network.py       # Network Security Groups audit (CIS Section 7.1)
│       ├── keyvault.py      # Key Vault audit (CIS Section 8.3)
│       └── identity.py      # Identity & Access Management audit (CIS Section 1)
├── templates/               # HTML report templates (Jinja2)
├── tests/                   # Unit & integration tests
│   └── test_conn.py
├── cli.py                   # Main CLI entry point
├── requirements.txt         # Python dependencies
├── LICENSE                  # Apache 2.0 License
└── README.md
```

---

## 2. Prerequisites & Authentication

### Prerequisites
- **Python**: 3.10 or higher
- **Azure Permissions**: Read-only permissions on the target subscription (e.g., built-in role **Reader**).

### Authentication Methods
The tool leverages Azure's `DefaultAzureCredential` (`auditor/auth.py`), supporting:
- **Azure CLI (Local development)**:
  ```bash
  az login
  az account set --subscription <SUBSCRIPTION_ID>
  ```
- **Service Principal (CI/CD & Automation)** via environment variables:
  ```bash
  export AZURE_CLIENT_ID="<client-id>"
  export AZURE_CLIENT_SECRET="<client-secret>"
  export AZURE_TENANT_ID="<tenant-id>"
  export AZURE_SUBSCRIPTION_ID="<subscription-id>"
  ```

---

## 3. Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/<owner>/azure-sec-scanner.git
   cd azure-sec-scanner
   ```

2. **Create and activate a virtual environment**:
   - On Linux / macOS:
     ```bash
     python3 -m venv .venv
     source .venv/bin/activate
     ```
   - On Windows (PowerShell):
     ```powershell
     python -m venv .venv
     .\.venv\Scripts\Activate.ps1
     ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 4. Usage & CLI Options

Run the CLI tool by specifying the Azure Subscription ID (or provide it via the `AZURE_SUBSCRIPTION_ID` environment variable):

```bash
python cli.py --subscription-id <SUBSCRIPTION_ID>
```

### CLI Options

| Argument | Environment Variable | Required | Description |
| :--- | :--- | :---: | :--- |
| `--subscription-id` | `AZURE_SUBSCRIPTION_ID` | Yes | Target Azure Subscription ID to audit |
| `-h`, `--help` | — | No | Show help message and exit |

---

## 5. Security Scanners & CIS Controls

All security checks follow the **CIS Microsoft Azure Foundations Benchmark v7.0.0**.

### 5.1 Storage Accounts Scanner (CIS Section 9.2)

Audits Azure Storage Accounts for public exposure, protocol security, and access control.

#### Evaluated CIS Controls

| CIS ID | Control Title | Severity | Security Impact | Module |
| :--- | :--- | :---: | :--- | :--- |
| **9.2.1.1** | Ensure Storage Account Public Network Access is Disabled | `HIGH` | Exposes data directly to the internet; risk of unauthorized exfiltration. | `storage.py` |
| **9.2.1.2** | Ensure Default Network Access Rule is Set to Deny | `HIGH` | Allows non-whitelisted traffic to reach the storage endpoint. | `storage.py` |
| **9.2.3** | Ensure 'Secure transfer required' is Enabled (HTTPS only) | `HIGH` | Unencrypted cleartext transit exposes data to eavesdropping / MITM. | `storage.py` |
| **9.2.4** | Ensure Minimum TLS Version is Set to TLS 1.2 | `MEDIUM` | Older TLS versions (1.0/1.1) have known protocol vulnerabilities. | `storage.py` |
| **9.2.5** | Ensure 'Allow Blob Public Access' is Disabled | `HIGH` | Anonymous users can read containers and blobs without authentication. | `storage.py` |

---

### 5.2 Network Security Groups (NSG) Scanner (CIS Section 7.1)

Enforces the principle of least privilege across Azure Virtual Networks (VNets) by auditing inbound security rules for public internet exposure against the CIS Microsoft Azure Foundations Benchmark v7.0.0 (Section 7.1). Specifically, it detects unrestricted access (`0.0.0.0/0`, `Internet`, or `*`) to critical management ports—RDP (`3389/TCP`) and SSH (`22/TCP`)—which exposes virtual machines to brute-force attacks and subsequent lateral movement.

#### Evaluated CIS Controls

| CIS ID | Control Title | Service / Protocol | Port | Severity | Security Impact | Module |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **7.1.1** | Ensure that RDP Access from the Internet is Restricted | `RDP / TCP` | `3389` | `CRITICAL` | Rapid external discovery; high risk of brute-force attacks, ransomware, and lateral movement. | `network.py` |
| **7.1.5** | Ensure that SSH Access from the Internet is Restricted | `SSH / TCP` | `22` | `CRITICAL` | Automated port scanning, credential stuffing, and unauthorized shell access leading to pivot. | `network.py` |

#### Sample Console Output

```text
[*] Authenticating via DefaultAzureCredential...
[*] Scanning Network Security Groups in subscription <SUBSCRIPTION_ID>...

======================================================================
 RAPPORT D'AUDIT DE SÉCURITÉ AZURE : 1 ANOMALIES TROUVÉES
======================================================================
[CRITICAL] CIS 7.1.1    | nsg-prod-web-01/Allow-RDP-Any     -> Le port RDP (3389) est ouvert sur Internet via la règle 'Allow-RDP-Any'. Source configurée : 0.0.0.0/0.
======================================================================
```

#### Remediation & Audit Trail

1. **Immediate Azure CLI Remediation**

   Remove non-compliant inbound rules exposing management ports to the public internet:
   ```bash
   az network nsg rule delete \
     --resource-group <resource-group> \
     --nsg-name <network-security-group> \
     --name <rule-name>
   ```

   Alternatively, if remote administrative access is strictly required, restrict the rule to a trusted corporate CIDR range:
   ```bash
   az network nsg rule update \
     --resource-group <resource-group> \
     --nsg-name <network-security-group> \
     --name <rule-name> \
     --source-address-prefixes <trusted-address-range>
   ```

2. **Modern Zero Trust Alternatives**
   - **Azure Bastion:** Eliminates the need for public IP addresses on Virtual Machines and avoids exposing `3389/TCP` or `22/TCP` to the internet by brokering encrypted RDP/SSH sessions over TLS (`443/TCP`) with Microsoft Entra ID MFA and Conditional Access enforcement.
   - **Just-In-Time (JIT) VM Access:** Available via Microsoft Defender for Cloud (Defender for Servers Plan 2), JIT locks down inbound management traffic by default and opens ports only for time-bound, approved administrative sessions.

3. **Audit Trail & Continuous Compliance**
   - Exporting scan results to structured Markdown reports creates a timestamped, human-readable audit trail to demonstrate CIS compliance to internal security teams and external auditors.
   - Integrating the CLI scanner into CI/CD pipelines (e.g., GitHub Actions or Azure DevOps) enforces continuous drift detection and prevents misconfigured NSG rules from persisting in production.

---

### 5.3 Key Vault Scanner (CIS Section 8.3)

Audits Azure Key Vault instances for security posture, access control policies, and network isolation.

#### Evaluated CIS Controls

| CIS ID | Control Title | Severity | Security Impact | Module |
| :--- | :--- | :---: | :--- | :--- |
| **8.3.8** | Ensure that Purge Protection is Enabled for Key Vaults | `HIGH` | Deleted secrets can be permanently purged immediately, bypassing soft delete. | `keyvault.py` |
| **8.3.9** | Ensure Key Vault uses Azure RBAC for Authorization | `MEDIUM` | Legacy vault access policies lack fine-grained, centralized access governance. | `keyvault.py` |
| **8.3.10** | Ensure Default Network Action for Key Vault is Set to Deny | `HIGH` | Vault endpoint remains reachable by unauthorized network traffic. | `keyvault.py` |
| **8.3.11** | Ensure Key Vault Public Network Access is Disabled | `HIGH` | Publicly exposed Key Vault endpoints increase attack surface against credentials. | `keyvault.py` |

---

### 5.4 Identity & Access Management Scanner (CIS Section 1)

*In development.* Focuses on auditing Microsoft Entra ID (formerly Azure AD) configurations:
- MFA enforcement for administrative and privileged roles.
- Stale or over-privileged guest accounts and Service Principals.
- Deprecated authentication protocols.

---

## 6. Audit Reports & Output Formats

- **Console Report (`auditor/reporters/console.py`)**: Real-time terminal output, ranked by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- **Markdown Report (`auditor/reporters/markdown.py`)**: Exportable Markdown summaries suitable for git commits, compliance reviews, and PR comments.
- **HTML Report (`templates/`)**: Web-friendly audit summaries rendered via Jinja2 templates.

---

## 7. Remediation & Best Practices

1. **Adopt Zero Trust Principles**: Eliminate direct management port access over public IPs using Azure Bastion or VPN/ExpressRoute.
2. **Automate Continuous Compliance**: Schedule audit scans using GitHub Actions or Azure DevOps Pipelines to detect configuration drift.
3. **Enforce Azure Policy**: Implement guardrails with `Deny` effects (e.g., prevent creation of storage accounts with public access or NSGs with `0.0.0.0/0` on port 22/3389).

---

## 8. Testing & Development

Run the test suite using `pytest`:

```bash
pytest tests/ -v
```

To test connectivity against a test resource group:
```bash
python tests/test_conn.py
```

---

## 9. License & Contributing

- **License**: This project is licensed under the [Apache 2.0 License](LICENSE).
- **Contributing**: Pull requests and issue reports are welcome. Please ensure new checks adhere to the CIS Microsoft Azure Foundations Benchmark standard.