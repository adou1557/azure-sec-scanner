from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ClientAuthenticationError
def get_azure_credential() -> DefaultAzureCredential:
    """Instancie et retourne la chaîne d'authentification par défaut."""
    try:
        return DefaultAzureCredential()
    except Exception as e:
        raise ClientAuthenticationError(f"Erreur d'initialisation des identifiants : {e}")