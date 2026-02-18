# Task 10: Shared Responsibility Model

## Descripcion
Politicas OPA/Rego que implementan compliance-as-code para validar el cumplimiento
del modelo de responsabilidad compartida en la arquitectura hibrida de XYZ.

## Politicas
- `opa-policies/iam_policy.rego` - Validacion de IAM (MFA, least privilege)
- `opa-policies/encryption_policy.rego` - Validacion de cifrado (TDE, TLS)
- `opa-policies/network_policy.rego` - Validacion de segmentacion de red

## Uso con OPA
```bash
# Evaluar politicas
opa eval -i input.json -d opa-policies/ "data.xyz.security"
```

## Referencia
Documento completo: Secciones 10.1 a 10.5
