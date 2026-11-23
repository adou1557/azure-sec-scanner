import os
from dotenv import load_dotenv
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

load_dotenv()

subscription_id = os.environ["AZURE_SUBSCRIPTION_ID"]
credential = DefaultAzureCredential()
client = ResourceManagementClient(credential, subscription_id)

print("=== Ressources détectées dans rg-sec-scanner-lab ===")
for res in client.resources.list_by_resource_group("rg-sec-scanner-lab"):
    print(f"[OK] {res.name} -> {res.type}")