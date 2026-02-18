# Task 12: Kubernetes vs Containers

## Descripcion
Comparacion practica entre Docker Compose (contenedores standalone) y Kubernetes
para el despliegue del portal financiero XYZ.

## Docker Compose (desarrollo/produccion simple)
```bash
cd docker-compose/
docker-compose up -d
```

## Kubernetes (produccion escalable)
```bash
kubectl apply -f kubernetes/
```

## Comparacion
| Aspecto | Docker Compose | Kubernetes |
|---------|---------------|------------|
| Escalado | Manual | Automatico (HPA) |
| Self-healing | restart: always | Reschedule + probes |
| Networking | Bridge | Services + Ingress |
| Secrets | .env files | Secrets API + Vault |

## Referencia
Documento completo: Secciones 12.1 a 12.5
