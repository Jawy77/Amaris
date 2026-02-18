# =============================================================================
# IAM Policy - Shared Responsibility Validation
# Referencia: Task 10 - Responsabilidad del CLIENTE en todos los modelos
# =============================================================================

package xyz.security.iam

# Verificar MFA habilitado en todos los usuarios IAM
deny[msg] {
    user := input.iam_users[_]
    not user.mfa_enabled
    msg := sprintf(
        "VIOLACION: Usuario IAM '%s' no tiene MFA habilitado. [ISO 27001 A.8.5, NIST IA-2]",
        [user.name]
    )
}

# No permitir politicas IAM con acceso total (*:*)
deny[msg] {
    policy := input.iam_policies[_]
    policy.effect == "Allow"
    policy.action == "*"
    policy.resource == "*"
    msg := sprintf(
        "VIOLACION: Politica IAM '%s' otorga acceso total (*:*). Viola minimo privilegio. [NIST AC-6]",
        [policy.name]
    )
}

# Service accounts con maximo 3 roles
deny[msg] {
    sa := input.service_accounts[_]
    count(sa.roles) > 3
    msg := sprintf(
        "ADVERTENCIA: Service account '%s' tiene %d roles (max recomendado: 3). [NIST AC-6]",
        [sa.name, count(sa.roles)]
    )
}

# No permitir acceso con usuario root/admin de cloud
deny[msg] {
    user := input.iam_users[_]
    user.is_root == true
    user.last_used_days_ago < 30
    msg := sprintf(
        "CRITICO: Cuenta root/admin '%s' fue usada hace %d dias. No usar para operaciones diarias.",
        [user.name, user.last_used_days_ago]
    )
}

# Verificar rotacion de access keys (< 90 dias)
deny[msg] {
    key := input.access_keys[_]
    key.age_days > 90
    msg := sprintf(
        "VIOLACION: Access key '%s' de usuario '%s' tiene %d dias. Maximo: 90. [PCI-DSS 8.2.4]",
        [key.key_id, key.user, key.age_days]
    )
}
