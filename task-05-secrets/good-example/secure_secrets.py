"""
Patrones CORRECTOS de gestion de secrets - Portal Financiero XYZ
Demuestra como manejar credenciales de forma segura.

Referencia: Task 5 Seccion 5.5
"""

import os
import json
from functools import lru_cache


# =============================================================================
# Patron 1: Variables de Entorno (solucion minima aceptable)
# =============================================================================

def get_config_from_env():
    """Obtener configuracion desde variables de entorno."""
    return {
        "database_url": os.environ["DATABASE_URL"],       # Falla si no existe
        "stripe_key": os.environ.get("STRIPE_SECRET_KEY"), # None si no existe
        "jwt_secret": os.environ["JWT_SECRET"],
        "debug": os.environ.get("DEBUG", "false").lower() == "true",
    }


# =============================================================================
# Patron 2: HashiCorp Vault
# =============================================================================

def get_secret_from_vault(secret_path, key):
    """
    Obtener un secret desde HashiCorp Vault.
    Requiere: pip install hvac
    """
    import hvac

    client = hvac.Client(url=os.environ["VAULT_ADDR"])

    # Autenticacion via Kubernetes Service Account (en K8s)
    if os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token"):
        with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
            jwt_token = f.read()
        client.auth.kubernetes.login(
            role="financial-portal",
            jwt=jwt_token
        )
    else:
        # Autenticacion via token (para desarrollo)
        client.token = os.environ.get("VAULT_TOKEN")

    # Leer secret
    secret = client.secrets.kv.v2.read_secret_version(path=secret_path)
    return secret["data"]["data"][key]


# =============================================================================
# Patron 3: AWS Secrets Manager
# =============================================================================

@lru_cache(maxsize=10)
def get_secret_aws(secret_name, region="us-east-1"):
    """
    Obtener un secret desde AWS Secrets Manager.
    Requiere: pip install boto3
    """
    import boto3

    client = boto3.client("secretsmanager", region_name=region)
    response = client.get_secret_value(SecretId=secret_name)
    return json.loads(response["SecretString"])


# =============================================================================
# Patron 4: GCP Secret Manager
# =============================================================================

def get_secret_gcp(project_id, secret_id, version="latest"):
    """
    Obtener un secret desde GCP Secret Manager.
    Requiere: pip install google-cloud-secret-manager
    """
    from google.cloud import secretmanager

    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")


# =============================================================================
# Uso en aplicacion
# =============================================================================

def create_database_connection():
    """Ejemplo de conexion segura a base de datos."""
    # Opcion A: Desde variable de entorno
    db_url = os.environ.get("DATABASE_URL")

    if not db_url:
        # Opcion B: Desde Vault (credenciales dinamicas)
        creds = get_secret_from_vault("database/creds/financial-app", "connection_string")
        db_url = creds

    # Conectar sin exponer credenciales en codigo
    import sqlalchemy
    engine = sqlalchemy.create_engine(db_url)
    return engine


if __name__ == "__main__":
    print("=== Patrones de Gestion Segura de Secrets ===")
    print()
    print("Patron 1: Variables de entorno")
    print("  export DATABASE_URL='postgresql://...'")
    print("  python app.py")
    print()
    print("Patron 2: HashiCorp Vault")
    print("  vault kv put secret/financial-portal db_password=xxx")
    print()
    print("Patron 3: AWS Secrets Manager")
    print("  aws secretsmanager create-secret --name financial-portal/db")
    print()
    print("Patron 4: GCP Secret Manager")
    print("  gcloud secrets create financial-portal-db --data-file=secret.txt")
