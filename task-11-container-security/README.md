# Task 11: Security in Container Architectures

## Descripcion
Implementaciones de seguridad para contenedores en todo el ciclo de vida.

## Componentes

### Dockerfile Hardened
`Dockerfile.secure` - Imagen con mejores practicas:
- Base Alpine minimal
- Usuario non-root
- Multi-stage build
- Health check
- Sin herramientas de build

### Kubernetes Security
- `kubernetes/deployment-secure.yaml` - SecurityContext completo
- `kubernetes/network-policy.yaml` - Default deny-all
- `kubernetes/pod-security-standard.yaml` - PSA Restricted
- `kubernetes/rbac.yaml` - Minimo privilegio

### Falco (Runtime Detection)
- `falco/falco-rules.yaml` - Reglas custom para portal financiero

### OPA Gatekeeper
- `opa-gatekeeper/constraint-template.yaml` - Template de politicas
- `opa-gatekeeper/constraint.yaml` - Constraint aplicado

## Referencia
Documento completo: Secciones 11.1 a 11.3
