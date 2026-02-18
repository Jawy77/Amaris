# Task 6: Seguridad Cloud + OnPremise

## Descripcion
Infraestructura como codigo (IaC) para la arquitectura hibrida segura del portal financiero XYZ.

## Componentes

### Terraform (GCP)
- VPC con 3 subnets segmentadas (DMZ, App, Data)
- Firewall rules deny-all + allow-list
- VPN Site-to-Site (IPSec) para interconexion Cloud-OnPrem
- Cloud NAT para egress controlado

### Kubernetes Security
- Network Policies (default deny-all)
- RBAC (minimo privilegio)
- Pod Security Standards (restricted)

## Uso
```bash
# Terraform
cd terraform
terraform init
terraform plan
terraform apply

# Kubernetes (requiere cluster activo)
kubectl apply -f kubernetes/
```

## Referencia
Documento completo: Seccion 6.1 a 6.4
