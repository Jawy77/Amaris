# Amaris Consulting - Regional Security Expert Assessment

## XYZ Financial Services Portal - Implementacion Practica de Seguridad

Implementaciones tecnicas y practicas para la evaluacion de seguridad del portal web financiero de XYZ. Cada directorio de tarea contiene codigo ejecutable, configuraciones desplegables y pipelines automatizados.

---

## Estructura del Proyecto

```
amaris/
├── docs/                              # Documento teorico y diagramas originales
├── task-01-risk-analysis/             # Registro de riesgos YAML + heatmap Python
├── task-02-security-controls/         # Configs Nginx: WAF, headers, rate limiting
├── task-03-architecture/              # Diagramas Mermaid de arquitectura
├── task-04-sast-dast/                 # App vulnerable + Semgrep + OWASP ZAP
├── task-05-secrets/                   # Gestion de secrets: ejemplos + scanning
├── task-06-cloud-onprem/              # Terraform (GCP) + Kubernetes manifests
├── task-07-api-security/              # API Gateway mTLS + OAuth2
├── task-08-devsecops/                 # Dockerfile hardened + pipeline CI/CD
├── task-09-data-masking-encryption/   # Masking, AES-256, tokenizacion (Python)
├── task-10-shared-responsibility/     # Politicas OPA/Rego compliance-as-code
├── task-11-container-security/        # Hardened containers + Falco + Gatekeeper
├── task-12-k8s-vs-containers/         # Docker Compose vs Kubernetes
└── .github/workflows/                 # Pipelines DevSecOps (GitHub Actions)
```

## Prerrequisitos

- Python 3.11+
- Docker (para tasks 4, 8, 11, 12)
- Terraform >= 1.5 (para task 6)
- kubectl (para tasks 6, 11, 12)

## Quick Start

```bash
# Task 1: Generar heatmap de riesgos
cd task-01-risk-analysis
pip install -r requirements.txt
python risk_matrix.py

# Task 9: Demo de masking y cifrado
cd task-09-data-masking-encryption
pip install -r requirements.txt
python masking.py
python encryption.py
python tokenization.py

# Task 4: Ejecutar SAST con Semgrep
cd task-04-sast-dast
semgrep --config sast/.semgrep.yml vulnerable-app/
```

## Tareas

| # | Tarea | Descripcion | Tecnologias |
|---|-------|-------------|-------------|
| 1 | [Analisis de Riesgos](task-01-risk-analysis/) | Registro YAML + heatmap visual | Python, matplotlib, PyYAML |
| 2 | [Controles de Seguridad](task-02-security-controls/) | Configs WAF, headers, rate limiting | Nginx, ModSecurity |
| 3 | [Arquitectura](task-03-architecture/) | Diagramas de arquitectura segura | Mermaid |
| 4 | [SAST y DAST](task-04-sast-dast/) | App vulnerable + escaneo automatizado | Flask, Semgrep, OWASP ZAP |
| 5 | [Secrets](task-05-secrets/) | Gestion segura de credenciales | Gitleaks, Vault, Python |
| 6 | [Cloud + OnPremise](task-06-cloud-onprem/) | Infraestructura segura | Terraform, Kubernetes |
| 7 | [Seguridad API](task-07-api-security/) | API Gateway con mTLS y OAuth2 | Nginx, Python, OpenSSL |
| 8 | [DevSecOps](task-08-devsecops/) | Pipeline CI/CD con seguridad | GitHub Actions, Docker |
| 9 | [Masking vs Cifrado](task-09-data-masking-encryption/) | Demos de proteccion de datos | Python, cryptography |
| 10 | [Shared Responsibility](task-10-shared-responsibility/) | Compliance as code | OPA/Rego |
| 11 | [Container Security](task-11-container-security/) | Hardening de contenedores | Docker, K8s, Falco, OPA |
| 12 | [K8s vs Containers](task-12-k8s-vs-containers/) | Comparacion practica | Docker Compose, Kubernetes |

## CI/CD Pipelines

| Workflow | Trigger | Herramientas |
|----------|---------|--------------|
| [Security Pipeline](.github/workflows/security-pipeline.yml) | Push a main | Semgrep, Trivy, Checkov, ZAP |
| [SAST Scan](.github/workflows/sast-scan.yml) | Pull Request | Semgrep |
| [DAST Scan](.github/workflows/dast-scan.yml) | Manual / Push main | OWASP ZAP |
| [Container Scan](.github/workflows/container-scan.yml) | Cambios en Dockerfile | Trivy |
| [Secret Scan](.github/workflows/secret-scan.yml) | Push / PR | Gitleaks |

## Documento Teorico

El analisis completo se encuentra en [docs/Regional_Security_Expert_Response.md](docs/Regional_Security_Expert_Response.md)

---

**Candidato:** Amaris Consulting - Regional Security Expert Assessment
**Empresa:** XYZ Financial Services
**Fecha:** Febrero 2026
