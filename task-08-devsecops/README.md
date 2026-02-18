# Task 8: DevSecOps

## Descripcion
Pipeline DevSecOps completo con seguridad integrada en cada fase del SDLC.

## Componentes

### Dockerfile Hardened
Multi-stage build con mejores practicas de seguridad:
- Base image Alpine (minima superficie de ataque)
- Usuario non-root
- Health check
- Sin herramientas de build en imagen final

### Pipeline CI/CD
Ver `.github/workflows/security-pipeline.yml` - Pipeline completo:
1. Secret Scanning (Gitleaks)
2. SAST (Semgrep)
3. SCA (Dependency Check)
4. Container Image Scan (Trivy)
5. IaC Scan (Checkov)
6. DAST (OWASP ZAP)

## Referencia
Documento completo: Secciones 8.1 a 8.4
