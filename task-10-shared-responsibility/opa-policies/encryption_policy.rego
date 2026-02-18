# =============================================================================
# Encryption Policy - Shared Responsibility Validation
# Referencia: Task 10 - Responsabilidad del CLIENTE (IaaS/PaaS/CaaS)
# =============================================================================

package xyz.security.encryption

# Bases de datos deben tener cifrado en reposo
deny[msg] {
    db := input.databases[_]
    not db.encryption_at_rest
    msg := sprintf(
        "CRITICO: Base de datos '%s' no tiene cifrado en reposo. [PCI-DSS 3.4, ISO 27001 A.8.24]",
        [db.name]
    )
}

# TLS debe ser version 1.3
deny[msg] {
    endpoint := input.endpoints[_]
    endpoint.tls_version != "1.3"
    msg := sprintf(
        "VIOLACION: Endpoint '%s' usa TLS %s. Minimo requerido: TLS 1.3. [PCI-DSS 4.1]",
        [endpoint.name, endpoint.tls_version]
    )
}

# Backups deben estar cifrados
deny[msg] {
    backup := input.backups[_]
    not backup.encrypted
    msg := sprintf(
        "VIOLACION: Backup '%s' no esta cifrado. [ISO 27001 A.8.13]",
        [backup.name]
    )
}

# Algoritmos de cifrado deben ser fuertes
deny[msg] {
    db := input.databases[_]
    db.encryption_at_rest
    db.encryption_algorithm != "AES-256"
    msg := sprintf(
        "ADVERTENCIA: Base de datos '%s' usa %s. Recomendado: AES-256. [PCI-DSS 3.4]",
        [db.name, db.encryption_algorithm]
    )
}

# Claves de cifrado deben gestionarse con KMS/HSM
deny[msg] {
    db := input.databases[_]
    db.encryption_at_rest
    not db.key_management_service
    msg := sprintf(
        "VIOLACION: Base de datos '%s' no usa KMS/HSM para gestion de claves. [PCI-DSS 3.5]",
        [db.name]
    )
}
