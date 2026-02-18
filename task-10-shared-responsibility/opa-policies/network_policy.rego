# =============================================================================
# Network Policy - Shared Responsibility Validation
# Referencia: Task 10 - Responsabilidad del CLIENTE
# =============================================================================

package xyz.security.network

# Bases de datos no deben tener acceso publico
deny[msg] {
    db := input.databases[_]
    db.public_access == true
    msg := sprintf(
        "CRITICO: Base de datos '%s' tiene acceso publico. Debe estar en subnet privada. [NIST SC-7]",
        [db.name]
    )
}

# Namespaces de K8s deben tener NetworkPolicy default-deny
deny[msg] {
    ns := input.namespaces[_]
    not ns.has_default_deny_policy
    msg := sprintf(
        "VIOLACION: Namespace '%s' no tiene NetworkPolicy default-deny. [CIS K8s Benchmark 5.3]",
        [ns.name]
    )
}

# Firewalls deben ser deny-all por defecto
deny[msg] {
    fw := input.firewalls[_]
    fw.default_action != "DENY"
    msg := sprintf(
        "VIOLACION: Firewall '%s' tiene accion por defecto '%s'. Debe ser DENY. [NIST SC-7]",
        [fw.name, fw.default_action]
    )
}

# VPN debe estar activa para conexion Cloud-OnPrem
deny[msg] {
    conn := input.cloud_onprem_connections[_]
    not conn.vpn_enabled
    msg := sprintf(
        "CRITICO: Conexion Cloud-OnPrem '%s' no usa VPN. Datos expuestos en transito. [ISO 27001 A.8.20]",
        [conn.name]
    )
}

# Subnets de datos deben ser privadas
deny[msg] {
    subnet := input.subnets[_]
    subnet.zone == "data"
    subnet.has_internet_gateway
    msg := sprintf(
        "CRITICO: Subnet de datos '%s' tiene acceso a internet. Debe ser completamente privada.",
        [subnet.name]
    )
}
