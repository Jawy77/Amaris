# =============================================================================
# HashiCorp Vault - Configuracion para Portal Financiero XYZ
# Referencia: Task 5 Seccion 5.5
# =============================================================================

# Almacenamiento con Raft (alta disponibilidad)
storage "raft" {
  path    = "/vault/data"
  node_id = "vault-node-1"
}

# Listener HTTPS (obligatorio TLS)
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/vault/certs/vault.crt"
  tls_key_file  = "/vault/certs/vault.key"

  # Deshabilitar TLS solo en desarrollo
  # tls_disable = 1
}

# Auto-unseal con Cloud KMS (produccion)
seal "gcpckms" {
  project    = "xyz-financial-prod"
  region     = "us-east1"
  key_ring   = "vault-keyring"
  crypto_key = "vault-unseal-key"
}

# Direcciones del cluster
api_addr     = "https://vault.xyz-financial.internal:8200"
cluster_addr = "https://vault.xyz-financial.internal:8201"

# UI habilitada (acceso restringido por red)
ui = true

# Telemetria
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname         = true
}

# Auditoria - OBLIGATORIO para compliance (PCI-DSS 10.1)
audit {
  type = "file"
  path = "file"
  options = {
    file_path = "/vault/logs/audit.log"
    log_raw   = false
  }
}
