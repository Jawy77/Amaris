# Task 5: Analisis de Secrets Hardcodeados

## Descripcion
Demostracion practica de deteccion y gestion segura de secrets para el portal financiero XYZ.

## Estructura

### Ejemplo Malo (NO hacer esto)
`bad-example/` - Contiene credenciales FALSAS hardcodeadas para demostrar que detectan los scanners.

### Ejemplo Correcto
`good-example/` - Patrones seguros con variables de entorno, HashiCorp Vault, AWS/GCP Secrets Manager.

### Escaneo de Secrets
```bash
# Ejecutar escaneo
chmod +x scanning/scan_secrets.sh
./scanning/scan_secrets.sh
```

### HashiCorp Vault
`vault/` - Configuracion de referencia para Vault.

## Herramientas
- Gitleaks (pre-commit + CI/CD)
- TruffleHog (analisis de historial Git)
- detect-secrets (baseline approach)

## Referencia
Documento completo: Secciones 5.1 a 5.5
