# Diagramas de Arquitectura - Portal Financiero XYZ

## 1. Arquitectura de Defensa en Profundidad

```mermaid
flowchart TB
    subgraph L1["Capa 1: Usuarios Finales"]
        Browser["Browser Web\nTLS 1.3 | HSTS | CSP"]
        Mobile["App Movil\nCertificate Pinning"]
    end

    subgraph L2["Capa 2: Perimetro"]
        CDN["CDN + Anti-DDoS\nCloudFlare / CloudFront"]
        WAF["WAF - OWASP CRS\nRate Limiting | Bot Mgmt"]
    end

    subgraph L3["Capa 3: Presentacion"]
        LB["Load Balancer L7\nHealth Checks | SSL Offload"]
        RP["Reverse Proxy\nNginx/Envoy Hardened"]
    end

    subgraph L4["Capa 4: Aplicacion"]
        GW["API Gateway\nOAuth2 | JWT | Schema Validation"]
        FE["Frontend SPA\nReact/Angular"]
        BE["Backend API\nRESTful | Input Validation"]
    end

    subgraph L5["Capa 5: Servicios de Negocio"]
        direction LR
        Auth["Auth Service\nIAM/MFA"]
        Txn["Transaction\nService"]
        Files["File Upload\nSandbox"]
        Products["Products\nService"]
    end

    subgraph L6["Capa 6: Datos"]
        direction LR
        DB[("PostgreSQL\nAES-256 TDE\nPCI CDE")]
        Redis[("Redis\nSesiones")]
        S3[("Object Storage\nArchivos Cifrados")]
    end

    subgraph Security["Seguridad Transversal"]
        direction LR
        IAM["IAM"]
        HSM["HSM"]
        SIEM["SIEM/SOC"]
        IDS["IDS/IPS"]
        PKI["PKI"]
        VulnMgmt["Vuln Mgmt"]
    end

    L1 -->|HTTPS| L2
    L2 --> L3
    L3 --> L4
    GW --> FE
    GW --> BE
    L4 -->|mTLS| L5
    L5 --> L6
    Security -.->|Monitoreo 24/7| L2
    Security -.->|Monitoreo 24/7| L4
    Security -.->|Monitoreo 24/7| L6

    style L1 fill:#1a1a2e,stroke:#e94560,color:#fff
    style L2 fill:#1a1a2e,stroke:#e94560,color:#fff
    style L3 fill:#1a1a2e,stroke:#0f3460,color:#fff
    style L4 fill:#1a1a2e,stroke:#0f3460,color:#fff
    style L5 fill:#1a1a2e,stroke:#16213e,color:#fff
    style L6 fill:#1a1a2e,stroke:#16213e,color:#fff
    style Security fill:#0f3460,stroke:#e94560,color:#fff
```

## 2. Flujo de Transaccion Bancaria Segura

```mermaid
sequenceDiagram
    participant U as Usuario
    participant CDN as CDN + WAF
    participant GW as API Gateway
    participant Auth as Auth Service
    participant Txn as Transaction Service
    participant DB as Base de Datos
    participant SIEM as SIEM/SOC

    U->>CDN: 1. HTTPS Request (TLS 1.3)
    CDN->>CDN: 2. Validar WAF Rules
    CDN->>GW: 3. Forward (rate limit OK)
    GW->>GW: 4. Validar JWT + Schema
    GW->>Auth: 5. Verificar autorizacion (RBAC)
    Auth-->>GW: 6. Autorizado
    GW->>Auth: 7. Re-autenticacion MFA (step-up)
    Auth-->>GW: 8. MFA verificado
    GW->>Txn: 9. Ejecutar transferencia (mTLS)
    Txn->>Txn: 10. Validar idempotency key
    Txn->>Txn: 11. Verificar ownership del recurso
    Txn->>DB: 12. Transaccion (cifrado AES-256)
    DB-->>Txn: 13. Confirmacion
    Txn->>SIEM: 14. Audit trail inmutable
    Txn-->>GW: 15. Response
    GW-->>U: 16. Confirmacion + Notificacion

    Note over U,SIEM: Todos los pasos registrados en SIEM para correlacion
```

## 3. Arquitectura Cloud + OnPremise (Mejorada)

```mermaid
flowchart TB
    subgraph Users["Usuarios"]
        Browser["Browser"]
        MobileApp["App Movil"]
    end

    subgraph Edge["Capa de Borde - NUEVA"]
        CDN2["CDN + Anti-DDoS"]
        WAF2["WAF OWASP CRS"]
    end

    subgraph Cloud["CLOUD"]
        APIGW["API Gateway - NUEVO\nOAuth2 | Rate Limit | Schema"]
        WebApp["App Web"]

        subgraph K8S["Kubernetes - Hardened"]
            MS1["Microservicio 1\nNetwork Policy"]
            MS2["Microservicio 2\nmTLS"]
            MS3["Microservicio 3\nPSS Restricted"]
        end

        CloudDB[("BD Transaccional\nSubnet Privada\nCifrado TDE | DAM")]
    end

    subgraph VPNZone["Interconexion - NUEVA"]
        VPN["VPN Site-to-Site\nIPSec / Cloud Interconnect"]
        IDPS["IDS/IPS"]
    end

    subgraph OnPrem["ON-PREMISE"]
        OnPremLB["Load Balancer\nSSL Term | Health Checks"]
        APIVentas["API Ventas"]
        APICompras["API Compras"]
        APIBilling["API Billing"]
        OnPremDB[("BD OnPrem\nSubnet Privada\nAES-256 | Audit Log")]
    end

    subgraph Monitoring["SIEM Centralizado - NUEVO"]
        SIEMCentral["SIEM\nCloud + OnPrem\nLog Aggregation"]
    end

    Users -->|HTTPS| Edge
    Edge --> Cloud
    APIGW --> WebApp
    WebApp --> K8S
    K8S --> CloudDB
    Cloud -->|Cifrado| VPNZone
    VPNZone --> OnPrem
    OnPremLB --> APIVentas & APICompras & APIBilling
    APIVentas & APICompras & APIBilling --> OnPremDB
    Cloud -.->|Logs| Monitoring
    OnPrem -.->|Logs| Monitoring

    style Edge fill:#ff6b6b,stroke:#333,color:#fff
    style VPNZone fill:#ff6b6b,stroke:#333,color:#fff
    style Monitoring fill:#ff6b6b,stroke:#333,color:#fff
    style APIGW fill:#ff6b6b,stroke:#333,color:#fff
```

## 4. Integracion API con Proveedor 123 (Arquitectura Mejorada)

```mermaid
flowchart LR
    subgraph Provider["PROVEEDOR 123"]
        ProvDB[("BD")]
        ProvFW["Firewall"]
        ProvDB --> ProvFW
    end

    subgraph Security["Controles de Seguridad - XYZ"]
        FW["Firewall XYZ\nIP Whitelisting"]
        WAF3["WAF"]
        APIGW2["API Gateway\nOAuth2 Client Credentials\nRate Limit: 100 req/min\nJSON Schema Validation"]
    end

    subgraph XYZ["XYZ - APIs Internas"]
        LB2["Load Balancer"]
        API1["API 1\nVentas"]
        API2["API 2\nBilling"]
        SIEM2["SIEM\nMonitoreo"]
    end

    Provider <-->|"mTLS (TLS 1.3)\nVPN Dedicada\nIP Whitelisting"| Security
    FW --> WAF3 --> APIGW2
    APIGW2 --> LB2
    LB2 --> API1 & API2
    APIGW2 -.->|Audit Trail| SIEM2

    style Security fill:#4ecdc4,stroke:#333,color:#000
    style FW fill:#ff6b6b,stroke:#333,color:#fff
    style WAF3 fill:#ff6b6b,stroke:#333,color:#fff
    style APIGW2 fill:#ff6b6b,stroke:#333,color:#fff
```

## 5. Segmentacion de Red

```mermaid
flowchart TB
    subgraph DMZ["DMZ - Zona Desmilitarizada"]
        dmz_cdn["CDN"]
        dmz_waf["WAF"]
        dmz_lb["Load Balancer"]
    end

    subgraph AppZone["Zona de Aplicacion - Subnet Privada"]
        app_gw["API Gateway"]
        app_fe["Frontend"]
        app_be["Backend Services"]
    end

    subgraph DataZone["Zona de Datos - Subnet Aislada"]
        data_db[("PostgreSQL")]
        data_redis[("Redis")]
        data_s3[("Object Storage")]
    end

    subgraph MgmtZone["Zona de Gestion"]
        mgmt_bastion["Bastion Host"]
        mgmt_vpn["VPN + MFA"]
    end

    Internet((Internet)) -->|HTTPS 443| DMZ
    DMZ -->|"Firewall Rules\n(allow-list)"| AppZone
    AppZone -->|"Solo DB Port\n(5432, 6379)"| DataZone
    MgmtZone -->|"SSH via Bastion\nMFA Required"| AppZone
    MgmtZone -->|"Admin Access\nAudit Logged"| DataZone

    Internet -.->|BLOQUEADO| DataZone
    Internet -.->|BLOQUEADO| AppZone

    style DMZ fill:#ff9f43,stroke:#333,color:#000
    style AppZone fill:#54a0ff,stroke:#333,color:#fff
    style DataZone fill:#5f27cd,stroke:#333,color:#fff
    style MgmtZone fill:#10ac84,stroke:#333,color:#fff
```
