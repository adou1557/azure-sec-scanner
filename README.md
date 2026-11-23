# azure-sec-scanner



Azure Security Audit Scanner is a command-line tool built with Python and the Azure SDK. Designed to connect to an Azure subscription with read-only permissions, it automatically audits critical security configurations—such as accounts without MFA, publicly exposed Storage Accounts, overly permissive NSG rules, and Key Vault secrets without expiration dates—and generates a clean, actionable audit report in HTML or Markdown.



1 Organisation



azure-sec-scanner/

├── scanner/

│   ├── \_\_init\_\_.py

│   ├── auth.py          # Managing credentials and the Subscription ID

│   ├── checks/          # One module per audited service

│   │   ├── storage.py

│   │   ├── network.py

│   │   ├── keyvault.py

│   │   └── identity.py

│   └── reporter.py      # Generating a Markdown / HTML report

├── templates/           # HTML template (if you are using Jinja2)

├── tests/               # Unit tests (with mocks)

├── main.py              # CLI entry point

├── requirements.txt

└── README.md

