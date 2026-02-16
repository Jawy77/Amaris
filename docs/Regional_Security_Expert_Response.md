# Prueba Tecnica - Regional Security Expert

**Empresa:** XYZ - Servicios Financieros
**Rol:** Regional Security Expert
**Candidato:** Amaris Consulting
**Fecha:** 18 de febrero de 2026

---

## Tabla de Contenidos

1. [Tarea 1: Analisis de Riesgos](#tarea-1-analisis-de-riesgos)
2. [Tarea 2: Controles de Seguridad](#tarea-2-controles-de-seguridad-para-mitigar-riesgos)
3. [Tarea 3: Arquitectura de Alto Nivel](#tarea-3-arquitectura-de-alto-nivel)
4. [Tarea 4: Pruebas SAST y DAST](#tarea-4-pruebas-sast-y-dast)
5. [Tarea 5: Analisis de Secrets Hardcodeados](#tarea-5-analisis-de-secrets-hardcodeados)
6. [Tarea 6: Seguridad Cloud + OnPremise](#tarea-6-seguridad-de-arquitectura-cloud--onpremise)
7. [Tarea 7: Seguridad en Integracion API](#tarea-7-seguridad-en-integracion-api-con-proveedor-123)
8. [Task 8: DevSecOps](#task-8-devsecops)
9. [Task 9: Data Masking vs Data Encryption](#task-9-data-masking-vs-data-encryption)
10. [Task 10: Shared Responsibility Model](#task-10-shared-responsibility-model)
11. [Task 11: Container Security](#task-11-security-in-container-architectures)
12. [Task 12: Kubernetes vs Containers](#task-12-kubernetes-vs-containers)

---

# SECCION I: SEGURIDAD DEL PORTAL WEB (Tareas 1-3)

---

## Tarea 1: Analisis de Riesgos

### 1.1 Metodologia

El presente analisis de riesgos se realiza siguiendo la metodologia **ISO 27005:2022** (Gestion de Riesgos de Seguridad de la Informacion), complementada con el marco **NIST SP 800-30 Rev. 1** (Guide for Conducting Risk Assessments). La evaluacion considera:

- **Identificacion de activos** criticos del portal web
- **Identificacion de amenazas** por funcionalidad
- **Evaluacion de vulnerabilidades** potenciales
- **Determinacion de probabilidad e impacto** en una escala de 1 a 5
- **Calculo de riesgo** como Probabilidad x Impacto

### 1.2 Inventario de Activos Criticos

| ID | Activo | Clasificacion | Descripcion |
|----|--------|---------------|-------------|
| A-01 | Datos PII de clientes | Confidencial - Alto | Nombres, direcciones, telefono, email, documentos de identidad |
| A-02 | Credenciales de autenticacion | Confidencial - Critico | Contrasenas (hashes), tokens de sesion, factores de autenticacion |
| A-03 | Datos de tarjetas de credito | Confidencial - Critico (PCI-DSS) | Numeros de tarjeta (PAN), CVV, fecha de expiracion |
| A-04 | Datos transaccionales | Confidencial - Alto | Transferencias, pagos, montos, cuentas destino |
| A-05 | Sesiones de usuario | Confidencial - Alto | Tokens JWT/session IDs, estado de autenticacion |
| A-06 | Archivos cargados (quejas) | Interno | Documentos adjuntos de clientes, evidencias |
| A-07 | Informacion de productos financieros | Interno | Catalogo de productos, tasas, condiciones |
| A-08 | Logs y registros de auditoria | Interno - Alto | Trazabilidad de operaciones, evidencia forense |
| A-09 | Infraestructura del portal | Critico | Servidores, bases de datos, APIs, balanceadores |
| A-10 | Codigo fuente de la aplicacion | Confidencial - Alto | Logica de negocio, algoritmos, configuraciones |

### 1.3 Analisis de Amenazas por Funcionalidad

#### 1.3.1 Actualizacion de Datos Personales

| ID | Amenaza | Vulnerabilidad Asociada | CWE |
|----|---------|------------------------|-----|
| R-01 | Insecure Direct Object Reference (IDOR) | Falta de validacion de autorizacion a nivel de objeto | CWE-639 |
| R-02 | Inyeccion SQL | Falta de parametrizacion en consultas a BD | CWE-89 |
| R-03 | Cross-Site Scripting (XSS) | Falta de sanitizacion de entrada/salida | CWE-79 |
| R-04 | Manipulacion de datos PII | Falta de validacion server-side de campos | CWE-20 |
| R-05 | Data tampering en transito | Ausencia o configuracion debil de TLS | CWE-319 |

#### 1.3.2 Transferencias Bancarias

| ID | Amenaza | Vulnerabilidad Asociada | CWE |
|----|---------|------------------------|-----|
| R-06 | Fraude por CSRF | Ausencia de tokens anti-CSRF | CWE-352 |
| R-07 | Manipulacion de montos | Falta de validacion server-side de parametros financieros | CWE-472 |
| R-08 | Replay attacks | Ausencia de nonce/idempotency keys en transacciones | CWE-294 |
| R-09 | Race condition en saldos | Falta de bloqueo transaccional adecuado | CWE-362 |
| R-10 | Session hijacking | Tokens de sesion predecibles o no seguros | CWE-384 |

#### 1.3.3 Pago de Tarjetas de Credito

| ID | Amenaza | Vulnerabilidad Asociada | CWE |
|----|---------|------------------------|-----|
| R-11 | Robo de datos de tarjeta | Almacenamiento inseguro de PAN/CVV | CWE-312 |
| R-12 | Skimming digital (Magecart) | Inyeccion de scripts maliciosos en formularios de pago | CWE-506 |
| R-13 | Man-in-the-Middle (MitM) | Configuracion TLS debil o certificate pinning ausente | CWE-300 |
| R-14 | Incumplimiento PCI-DSS | Procesamiento directo de datos de tarjeta sin tokenizacion | N/A |
| R-15 | Information disclosure en logs | Datos de tarjeta registrados en logs de aplicacion | CWE-532 |

#### 1.3.4 Consulta de Productos Financieros

| ID | Amenaza | Vulnerabilidad Asociada | CWE |
|----|---------|------------------------|-----|
| R-16 | Information disclosure | Exposicion de datos internos en respuestas API | CWE-200 |
| R-17 | Enumeracion de recursos | Endpoints predecibles sin rate limiting | CWE-799 |
| R-18 | Broken Access Control | Acceso a productos no autorizados para el perfil del usuario | CWE-862 |

#### 1.3.5 Quejas/Reclamos con Carga de Archivos

| ID | Amenaza | Vulnerabilidad Asociada | CWE |
|----|---------|------------------------|-----|
| R-19 | Upload de webshell | Falta de validacion de tipo MIME real (magic bytes) | CWE-434 |
| R-20 | Malware via archivo | Ausencia de escaneo antimalware en uploads | CWE-434 |
| R-21 | XSS almacenado | Falta de sanitizacion en campos de texto del reclamo | CWE-79 |
| R-22 | Path traversal | Falta de sanitizacion del nombre de archivo | CWE-22 |
| R-23 | Denegacion de servicio (DoS) | Sin limites de tamano ni rate limiting en uploads | CWE-400 |

### 1.4 Evaluacion de Riesgos

**Escala de Probabilidad:**
| Nivel | Valor | Descripcion |
|-------|-------|-------------|
| Muy Baja | 1 | Evento raro, requiere habilidades avanzadas y condiciones especificas |
| Baja | 2 | Posible pero poco frecuente |
| Media | 3 | Probable, existen herramientas y tecnicas conocidas |
| Alta | 4 | Muy probable, vectores de ataque facilmente accesibles |
| Muy Alta | 5 | Casi seguro, ataques automatizados ampliamente disponibles |

**Escala de Impacto:**
| Nivel | Valor | Descripcion |
|-------|-------|-------------|
| Insignificante | 1 | Sin impacto financiero ni reputacional significativo |
| Menor | 2 | Impacto limitado, recuperacion rapida |
| Moderado | 3 | Perdida financiera moderada, afecta operaciones parcialmente |
| Mayor | 4 | Perdida financiera significativa, dano reputacional, sancion regulatoria |
| Catastrofico | 5 | Perdida masiva, compromiso total de datos, sancion regulatoria severa |

### 1.5 Matriz de Riesgos

| ID | Riesgo | Prob. | Impacto | Nivel (PxI) | Clasificacion |
|----|--------|-------|---------|-------------|---------------|
| R-11 | Robo de datos de tarjeta | 4 | 5 | **20** | **CRITICO** |
| R-19 | Upload de webshell | 4 | 5 | **20** | **CRITICO** |
| R-06 | Fraude por CSRF en transferencias | 4 | 5 | **20** | **CRITICO** |
| R-08 | Replay attacks en transacciones | 3 | 5 | **15** | **CRITICO** |
| R-02 | Inyeccion SQL | 3 | 5 | **15** | **CRITICO** |
| R-12 | Skimming digital | 3 | 5 | **15** | **CRITICO** |
| R-10 | Session hijacking | 4 | 4 | **16** | **CRITICO** |
| R-01 | IDOR en datos personales | 4 | 4 | **16** | **CRITICO** |
| R-07 | Manipulacion de montos | 3 | 5 | **15** | **CRITICO** |
| R-20 | Malware via archivo | 3 | 4 | **12** | **ALTO** |
| R-09 | Race condition en saldos | 3 | 4 | **12** | **ALTO** |
| R-21 | XSS almacenado | 4 | 3 | **12** | **ALTO** |
| R-03 | XSS en actualizacion de datos | 4 | 3 | **12** | **ALTO** |
| R-13 | Man-in-the-Middle | 2 | 5 | **10** | **ALTO** |
| R-22 | Path traversal | 3 | 3 | **9** | **ALTO** |
| R-04 | Manipulacion de datos PII | 3 | 3 | **9** | **ALTO** |
| R-14 | Incumplimiento PCI-DSS | 3 | 5 | **15** | **CRITICO** |
| R-15 | Info disclosure en logs | 3 | 4 | **12** | **ALTO** |
| R-05 | Data tampering en transito | 2 | 4 | **8** | **MEDIO** |
| R-16 | Information disclosure | 3 | 2 | **6** | **MEDIO** |
| R-17 | Enumeracion de recursos | 3 | 2 | **6** | **MEDIO** |
| R-18 | Broken Access Control (productos) | 2 | 3 | **6** | **MEDIO** |
| R-23 | DoS por uploads | 3 | 2 | **6** | **MEDIO** |

**Mapa de Calor de Riesgos:**

```
IMPACTO
  5 |  R-05      | R-08,R-02  | R-11,R-06  |            |
    |            | R-12,R-07  | R-19       |            |
    |            | R-14       |            |            |
  4 |            | R-20,R-09  | R-10,R-01  |            |
    |            | R-15       |            |            |
  3 | R-18       | R-22,R-04  | R-21,R-03  |            |
  2 |            | R-16,R-17  |            |            |
    |            | R-23       |            |            |
  1 |            |            |            |            |
    +------------+------------+------------+------------+
         1-2          3            4            5
                   PROBABILIDAD

Leyenda: CRITICO (>=15) | ALTO (9-14) | MEDIO (5-8) | BAJO (1-4)
```

---

## Tarea 2: Controles de Seguridad para Mitigar Riesgos

### 2.1 Marco de Referencia

Los controles se definen con base en:
- **ISO/IEC 27001:2022** - Anexo A (Controles de referencia)
- **NIST Cybersecurity Framework (CSF) 2.0**
- **OWASP Application Security Verification Standard (ASVS) v4.0**
- **PCI-DSS v4.0** (para funcionalidades de pago)

### 2.2 Controles por Categoria

#### 2.2.1 Autenticacion y Gestion de Identidad

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Autenticacion Multi-Factor (MFA) obligatoria para operaciones criticas (transferencias, pagos) | Preventivo | R-06, R-10 | ISO 27001 A.8.5, NIST IA-2 |
| Politica de contrasenas robustas (min. 12 caracteres, complejidad, sin contrasenas comunes - NIST SP 800-63B) | Preventivo | R-10 | OWASP ASVS 2.1 |
| Bloqueo de cuenta tras 5 intentos fallidos con desbloqueo temporal progresivo | Preventivo/Detectivo | R-10 | ISO 27001 A.8.5 |
| Re-autenticacion para operaciones sensibles (cambio de datos, transferencias altas) | Preventivo | R-01, R-06, R-07 | OWASP ASVS 3.7 |

#### 2.2.2 Autorizacion y Control de Acceso

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Role-Based Access Control (RBAC) con principio de minimo privilegio | Preventivo | R-01, R-18 | ISO 27001 A.8.3, NIST AC-6 |
| Validacion de autorizacion a nivel de objeto (Object-Level Authorization) en cada endpoint | Preventivo | R-01, R-18 | OWASP API Security Top 10 - API1 |
| Verificacion de propiedad del recurso antes de cualquier operacion CRUD | Preventivo | R-01, R-04 | OWASP ASVS 4.2 |

#### 2.2.3 Cifrado y Proteccion de Datos

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| TLS 1.3 obligatorio para todas las comunicaciones (HSTS con max-age >= 1 ano) | Preventivo | R-05, R-13 | ISO 27001 A.8.24, PCI-DSS 4.1 |
| Cifrado AES-256 en reposo para datos sensibles en base de datos | Preventivo | R-11, R-04 | PCI-DSS 3.4, ISO 27001 A.8.24 |
| Tokenizacion de datos de tarjeta (PAN) mediante proveedor certificado PCI-DSS | Preventivo | R-11, R-14 | PCI-DSS 3.4, 3.5 |
| Nunca almacenar CVV/CVC despues de la autorizacion | Preventivo | R-11, R-14 | PCI-DSS 3.2 |
| Key management mediante HSM (Hardware Security Module) | Preventivo | R-11 | PCI-DSS 3.5, 3.6 |

#### 2.2.4 Validacion de Entrada y Proteccion de Aplicacion

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Sanitizacion y validacion server-side de todos los inputs (whitelisting) | Preventivo | R-02, R-03, R-04, R-21 | OWASP ASVS 5.1 |
| Consultas parametrizadas / ORM para acceso a base de datos (nunca concatenacion) | Preventivo | R-02 | OWASP ASVS 5.3, CWE-89 |
| Content Security Policy (CSP) headers estrictos | Preventivo | R-03, R-12, R-21 | OWASP ASVS 14.4 |
| Web Application Firewall (WAF) con reglas OWASP CRS | Preventivo/Detectivo | R-02, R-03, R-06, R-21 | NIST SC-7 |
| Tokens anti-CSRF (Synchronizer Token Pattern o SameSite cookies) | Preventivo | R-06 | OWASP ASVS 4.2.2 |
| Idempotency keys para transacciones financieras | Preventivo | R-08 | CWE-294 |
| Rate limiting y throttling por usuario/IP | Preventivo | R-17, R-23 | OWASP ASVS 11.1 |

#### 2.2.5 Carga de Archivos (File Upload)

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Validacion de tipo MIME real (magic bytes), no solo extension | Preventivo | R-19 | OWASP ASVS 12.1 |
| Whitelist de tipos permitidos (PDF, JPG, PNG unicamente) | Preventivo | R-19, R-20 | CWE-434 |
| Limite de tamano de archivo (ej. 10MB maximo) | Preventivo | R-23 | OWASP ASVS 12.1 |
| Renombrado de archivos (UUID) y almacenamiento fuera del webroot | Preventivo | R-19, R-22 | OWASP ASVS 12.3 |
| Escaneo antimalware (ClamAV o similar) antes de almacenar | Detectivo | R-20 | ISO 27001 A.8.7 |
| Procesamiento de archivos en sandbox aislado | Preventivo | R-19, R-20 | NIST SC-44 |
| Servir archivos desde dominio separado (sin cookies de sesion) | Preventivo | R-19, R-21 | OWASP ASVS 12.5 |

#### 2.2.6 Gestion de Sesiones

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Tokens de sesion criptograficamente seguros (min. 128 bits de entropia) | Preventivo | R-10 | OWASP ASVS 3.2 |
| Timeout de sesion por inactividad (15 min para portal financiero) | Preventivo | R-10 | PCI-DSS 8.1.8 |
| Timeout absoluto de sesion (4 horas maximo) | Preventivo | R-10 | OWASP ASVS 3.3 |
| Invalidacion completa de sesion en logout (server-side) | Preventivo | R-10 | OWASP ASVS 3.3 |
| Flags de cookies: Secure, HttpOnly, SameSite=Strict | Preventivo | R-10, R-06 | OWASP ASVS 3.4 |
| Regeneracion de session ID post-autenticacion | Preventivo | R-10 | CWE-384 |

#### 2.2.7 Logging, Monitoreo y Respuesta

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| SIEM centralizado (Splunk, ELK, Microsoft Sentinel) con correlacion de eventos | Detectivo | Todos | ISO 27001 A.8.15, A.8.16 |
| Audit trail inmutable para todas las transacciones financieras | Detectivo | R-06, R-07, R-08, R-09 | PCI-DSS 10.1-10.3 |
| Alertas en tiempo real para eventos criticos (intentos fallidos, transferencias anomalas, uploads sospechosos) | Detectivo | Todos | NIST DE.AE, DE.CM |
| Proteccion de logs contra manipulacion (append-only, hash chain) | Preventivo | R-15 | ISO 27001 A.8.15 |
| Enmascaramiento de datos sensibles en logs (PAN, contrasenas) | Preventivo | R-15 | PCI-DSS 3.4, CWE-532 |
| Plan de respuesta a incidentes documentado y probado | Correctivo | Todos | ISO 27001 A.5.24-A.5.28, NIST RS |

#### 2.2.8 Cumplimiento PCI-DSS

| Control | Tipo | Riesgos Mitigados | Referencia |
|---------|------|-------------------|------------|
| Segmentacion del entorno de datos de tarjeta (CDE) | Preventivo | R-11, R-14 | PCI-DSS 1.3 |
| ASV scanning trimestral | Detectivo | R-11, R-14 | PCI-DSS 11.2 |
| Pruebas de penetracion anuales | Detectivo | Todos | PCI-DSS 11.3 |
| Proveedor de pagos certificado PCI-DSS Level 1 | Preventivo | R-11, R-14 | PCI-DSS 12.8 |

### 2.3 Mapeo Riesgos-Controles Consolidado

| Riesgo | Controles Principales |
|--------|----------------------|
| R-01 (IDOR) | RBAC, Object-Level Authorization, Re-autenticacion |
| R-02 (SQL Injection) | Parametrizacion, WAF, Validacion server-side |
| R-03 (XSS) | CSP, Sanitizacion, WAF, Output encoding |
| R-06 (CSRF) | Anti-CSRF tokens, SameSite cookies, Re-autenticacion |
| R-07 (Manipulacion de montos) | Validacion server-side, Firma de transacciones, Audit trail |
| R-08 (Replay attacks) | Idempotency keys, Nonces, Timestamps |
| R-10 (Session hijacking) | MFA, Tokens seguros, Timeout, Flags de cookies |
| R-11 (Robo datos tarjeta) | Tokenizacion, Cifrado, PCI-DSS, HSM |
| R-12 (Skimming) | CSP estricto, SRI (Subresource Integrity), Monitoreo de integridad |
| R-19 (Webshell upload) | Validacion MIME, Whitelist, Sandbox, Antimalware |
| R-20 (Malware upload) | Antimalware, Sandbox, Whitelist de tipos |
| R-21 (XSS stored) | Sanitizacion, CSP, Output encoding |
| R-22 (Path traversal) | Renombrado UUID, Almacenamiento fuera webroot |

---

## Tarea 3: Arquitectura de Alto Nivel

### 3.1 Descripcion General

La arquitectura propuesta para el portal web financiero de XYZ sigue un modelo de **defensa en profundidad** (Defense in Depth) con multiples capas de seguridad. Cada capa implementa controles especificos que complementan las demas, asegurando que la falla de un control no comprometa la seguridad global del sistema.

### 3.2 Capas de la Arquitectura

#### Capa 1: Usuario Final (Browser / Aplicacion Movil)

**Componentes:**
- Navegador web (desktop/mobile) con soporte TLS 1.3
- Aplicacion movil nativa (iOS/Android) opcional

**Controles de seguridad:**
- HTTPS obligatorio (HSTS preload con max-age de 2 anos)
- Certificate pinning en aplicacion movil
- Content Security Policy (CSP) level 3
- Subresource Integrity (SRI) para scripts de terceros
- Anti-clickjacking headers (X-Frame-Options: DENY)

#### Capa 2: Perimetro y Proteccion de Borde

**Componentes:**
- **CDN** (CloudFlare / AWS CloudFront) - Caching de contenido estatico y primera linea de defensa
- **Proteccion Anti-DDoS** (volumetrica y de capa 7)
- **WAF** (Web Application Firewall) con reglas OWASP Core Rule Set

**Controles de seguridad:**
- Mitigacion DDoS automatica (volumetrica L3/L4 y aplicacion L7)
- WAF con reglas para OWASP Top 10 (inyeccion, XSS, CSRF, etc.)
- Rate limiting global: 100 req/s por IP, 10 req/s para endpoints de autenticacion
- Geo-blocking si la operacion es regional
- Bot management y proteccion contra scraping
- SSL/TLS termination con certificados gestionados

#### Capa 3: Presentacion y Enrutamiento

**Componentes:**
- **Load Balancer** (L7) con health checks
- **Reverse Proxy** (Nginx/Envoy) con hardening

**Controles de seguridad:**
- Balanceo de carga con session affinity segura (no basada en IP)
- Health checks activos para deteccion de nodos comprometidos
- Headers de seguridad inyectados: X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy
- Conexiones backend sobre TLS (cifrado interno)
- Request/response size limits

#### Capa 4: Aplicacion

**Componentes:**
- **Frontend:** SPA (React/Angular) servido desde CDN o servidor estatico
- **Backend API:** RESTful API (Node.js/Java Spring Boot/.NET) desplegada en contenedores
- **API Gateway:** Punto unico de entrada para todas las APIs internas

**Controles de seguridad:**
- API Gateway con autenticacion OAuth 2.0 + JWT, rate limiting por usuario, validacion de schema (OpenAPI)
- Validacion de entrada server-side en cada endpoint
- Sanitizacion de salida (output encoding)
- CORS configurado restrictivamente (solo dominios de XYZ)
- Gestion de errores sin exposicion de informacion interna (error messages genericos)
- Circuit breaker pattern para resiliencia

#### Capa 5: Logica de Negocio y Servicios

**Componentes:**
- **Servicio de Autenticacion/Autorizacion** (Identity Provider)
- **Servicio de Transacciones** (transferencias, pagos)
- **Servicio de Gestion de Datos** (actualizacion de perfil)
- **Servicio de Archivos** (upload/download de documentos)
- **Servicio de Productos** (consulta de catalogo)
- **Servicio de Quejas/Reclamos**

**Controles de seguridad:**
- Comunicacion entre servicios mediante mTLS (mutual TLS)
- Cada servicio con su propio Service Account (minimo privilegio)
- Patron de transacciones: Saga pattern con compensacion para consistencia
- Servicio de archivos aislado en sandbox con procesamiento asincrono
- Validacion de reglas de negocio (limites de transferencia, horarios, etc.)

#### Capa 6: Datos

**Componentes:**
- **Base de datos principal:** PostgreSQL/MySQL con cifrado AES-256 (TDE)
- **Base de datos de sesiones:** Redis con cifrado en transito
- **Almacenamiento de archivos:** Object Storage (S3/GCS) con cifrado server-side
- **Sistema de backups:** Backups cifrados automaticos con retencion definida

**Controles de seguridad:**
- Cifrado en reposo AES-256 (Transparent Data Encryption)
- Cifrado en transito TLS para conexiones a BD
- Acceso restringido por subnet (solo capa de aplicacion)
- Database Activity Monitoring (DAM) para deteccion de consultas anomalas
- Backups cifrados con retencion de 90 dias, pruebas de restauracion trimestrales
- Separacion de BD: datos PCI en base de datos dedicada (CDE aislado)

#### Capa Transversal: Seguridad e Infraestructura

**Componentes y controles:**
- **IAM (Identity and Access Management):** Gestion centralizada de identidades, SSO, MFA, RBAC
- **HSM (Hardware Security Module):** Gestion de llaves criptograficas para tokenizacion y cifrado
- **SIEM/SOC:** Centro de Operaciones de Seguridad con monitoreo 24/7, correlacion de eventos, respuesta a incidentes
- **IDS/IPS:** Deteccion y prevencion de intrusiones en capas de red y host
- **PKI:** Infraestructura de clave publica para certificados internos (mTLS)
- **Vulnerability Management:** Escaneo continuo de vulnerabilidades

#### Red y Segmentacion

**Diseno de red:**
- **DMZ:** Capa perimetral (CDN, WAF, LB) en zona desmilitarizada
- **Zona de Aplicacion:** Servidores de aplicacion en subnet privada
- **Zona de Datos:** Bases de datos en subnet privada aislada (sin acceso directo desde internet)
- **Zona de Gestion:** Acceso administrativo via bastion host/VPN con MFA

**Controles:**
- Firewalls stateful entre cada zona (reglas allow-list, deny-all por defecto)
- Network segmentation con VLANs/Security Groups
- Micro-segmentacion a nivel de servicio (Network Policies en K8s si aplica)
- No hay ruteo directo entre zona DMZ y zona de datos

### 3.3 Diagrama Textual de la Arquitectura

```
                        ┌─────────────────────────────┐
                        │     USUARIOS FINALES         │
                        │   (Browser / App Movil)      │
                        └──────────┬──────────────────┘
                                   │ HTTPS (TLS 1.3)
                        ┌──────────▼──────────────────┐
                        │     CDN + Anti-DDoS          │
                        │   (CloudFlare/CloudFront)    │
                        └──────────┬──────────────────┘
                                   │
                        ┌──────────▼──────────────────┐
                        │     WAF (OWASP CRS)          │
                        │   Rate Limiting, Bot Mgmt    │
                        └──────────┬──────────────────┘
                                   │
                    ═══════════════ DMZ ════════════════
                                   │
                        ┌──────────▼──────────────────┐
                        │   LOAD BALANCER (L7)         │
                        │   Health Checks, SSL Offload │
                        └──────────┬──────────────────┘
                                   │
                    ═══════ ZONA DE APLICACION ═════════
                                   │
                        ┌──────────▼──────────────────┐
                        │      API GATEWAY             │
                        │  OAuth2, JWT, Rate Limit     │
                        │  Schema Validation           │
                        └──────────┬──────────────────┘
                                   │ mTLS
                    ┌──────────────┼──────────────────────┐
                    │              │                      │
              ┌─────▼─────┐ ┌─────▼──────┐  ┌───────────▼──────┐
              │ Auth Svc   │ │ Transaction│  │ File Upload Svc  │
              │ (IAM/MFA)  │ │ Service    │  │ (Sandbox)        │
              └─────┬─────┘ └─────┬──────┘  └───────────┬──────┘
                    │              │                      │
                    └──────────────┼──────────────────────┘
                                   │
                    ═══════ ZONA DE DATOS ══════════════
                                   │
                    ┌──────────────┼──────────────────────┐
                    │              │                      │
              ┌─────▼─────┐ ┌─────▼──────┐  ┌───────────▼──────┐
              │ PostgreSQL │ │ Redis      │  │ Object Storage   │
              │ (TDE)      │ │ (Sesiones) │  │ (Archivos)       │
              │ PCI CDE    │ └────────────┘  └──────────────────┘
              └───────────┘

     ┌─────────────────────────────────────────────────────────┐
     │              SEGURIDAD TRANSVERSAL                      │
     │  IAM │ HSM │ SIEM/SOC │ IDS/IPS │ PKI │ Vuln Mgmt     │
     └─────────────────────────────────────────────────────────┘
```

### 3.4 Flujo de una Transaccion Tipica (Transferencia Bancaria)

1. El usuario se autentica con MFA en su navegador
2. La solicitud HTTPS llega al CDN -> WAF (validacion de reglas)
3. El Load Balancer enruta al API Gateway
4. API Gateway valida JWT, verifica rate limits y schema
5. El servicio de transacciones recibe la solicitud con mTLS
6. Se verifica autorizacion (RBAC + ownership del recurso)
7. Se solicita re-autenticacion (MFA step-up) para la transferencia
8. Se ejecuta la transaccion con idempotency key (prevencion de replay)
9. Se registra en audit trail inmutable
10. Se cifra y almacena en BD (zona de datos aislada)
11. Se genera alerta/notificacion al usuario
12. SIEM registra y correlaciona el evento

### 3.5 Recomendacion para Diagramas

Para una presentacion profesional, se recomienda crear diagramas detallados utilizando herramientas como:
- **Draw.io / diagrams.net** (gratuito)
- **Lucidchart** (colaborativo)
- **Microsoft Visio**
- **PlantUML** para diagramas as code

Los diagramas deben incluir: flujos de datos, protocolos de comunicacion, zonas de seguridad y componentes de infraestructura con iconografia estandar.

---

# SECCION II: PRUEBAS DE SEGURIDAD Y SECRETS (Tareas 4-5)

---

## Tarea 4: Pruebas SAST y DAST

### 4.1 Definiciones

**SAST (Static Application Security Testing)** es una metodologia de prueba de seguridad que analiza el **codigo fuente, bytecode o binarios** de una aplicacion **sin ejecutarla**. Examina el codigo en busca de patrones que representen vulnerabilidades de seguridad conocidas, utilizando analisis de flujo de datos (data flow), analisis de flujo de control (control flow) y pattern matching.

**DAST (Dynamic Application Security Testing)** es una metodologia que prueba la aplicacion **en ejecucion** desde el exterior, simulando ataques reales contra la aplicacion desplegada. Interactua con la aplicacion a traves de sus interfaces (HTTP/HTTPS) enviando inputs maliciosos y analizando las respuestas para identificar vulnerabilidades explotables.

### 4.2 Comparacion Detallada

| Aspecto | SAST (Estatico) | DAST (Dinamico) |
|---------|-----------------|-----------------|
| **Que analiza** | Codigo fuente, bytecode, binarios | Aplicacion en ejecucion (black-box) |
| **Cuando se ejecuta** | En desarrollo (CI/CD, pre-commit, PR review) | En QA/Staging, pre-produccion, produccion periodica |
| **Perspectiva** | White-box (acceso total al codigo) | Black-box (sin acceso al codigo) |
| **Cobertura** | Todo el codigo, incluyendo paths no ejecutados | Solo funcionalidad alcanzable via interfaz |
| **Velocidad** | Rapido (minutos en CI/CD) | Mas lento (horas, requiere app desplegada) |
| **Falsos positivos** | Alto (requiere triaje manual) | Bajo (encuentra vulnerabilidades reales) |
| **Falsos negativos** | No detecta errores de configuracion runtime | No cubre codigo muerto o paths internos |
| **Tipos de vulnerabilidades** | Inyeccion SQL, XSS, buffer overflow, secrets hardcodeados, uso de funciones inseguras | XSS reflejado, CSRF, errores de autenticacion, misconfiguraciones del servidor, headers faltantes |
| **Dependencia del lenguaje** | Si (requiere parser por lenguaje) | No (trabaja a nivel HTTP) |
| **Requisito de ambiente** | Solo acceso al codigo | Ambiente desplegado y accesible |

### 4.3 Herramientas Recomendadas

#### SAST

| Herramienta | Tipo | Lenguajes | Caracteristicas Clave |
|-------------|------|-----------|----------------------|
| **SonarQube** (Community/Enterprise) | Comercial/Open Source | 30+ lenguajes | Analisis de calidad y seguridad, integracion CI/CD nativa, quality gates |
| **Semgrep** | Open Source | 30+ lenguajes | Reglas personalizables, rapido, bajo en falsos positivos, ideal para CI/CD |
| **Checkmarx SAST** | Comercial | 25+ lenguajes | Analisis de flujo profundo, integracion enterprise, reporte de compliance |
| **Fortify (Micro Focus)** | Comercial | 25+ lenguajes | Analisis exhaustivo, amplia base de reglas, integracion con ALM |
| **Snyk Code** | Comercial/Free tier | 10+ lenguajes | Integracion con IDEs, analisis en tiempo real, developer-friendly |
| **Bandit** | Open Source | Python | Especifico para Python, ligero, ideal para pre-commit hooks |

#### DAST

| Herramienta | Tipo | Caracteristicas Clave |
|-------------|------|-----------------------|
| **OWASP ZAP** | Open Source | Gratuito, activo mantenimiento, APIs para automatizacion, ideal para CI/CD |
| **Burp Suite Professional** | Comercial | Scanner avanzado, fuzzing, extensiones (BApp Store), estandar de la industria para pentesting |
| **Nuclei** | Open Source | Templates community-driven, rapido, orientado a CVEs y misconfiguraciones |
| **Acunetix** | Comercial | Deteccion avanzada, bajo falsos positivos, reportes de compliance |
| **Nessus** | Comercial | Mas orientado a infraestructura, complementa DAST web |
| **Nikto** | Open Source | Escaneo rapido de servidor web, deteccion de misconfiguraciones |

### 4.4 Escenarios de Implementacion para el Portal XYZ

#### Fase de Desarrollo (SAST)

```
Developer -> Commit -> Pre-commit hook (Semgrep/Bandit rapido)
                            |
                            v
                       Pull Request -> CI Pipeline:
                                       1. SonarQube analysis
                                       2. Semgrep custom rules
                                       3. Snyk Code scan
                                       4. Quality Gate check
                                            |
                                   PASS?----+----FAIL?
                                    |               |
                                    v               v
                               Merge allowed    PR bloqueado,
                                               dev corrige
```

**Reglas criticas para el portal financiero (SAST):**
- Deteccion de inyeccion SQL en queries a BD de transacciones
- Secrets hardcodeados (connection strings, API keys)
- Uso de funciones criptograficas debiles (MD5, SHA1 para passwords)
- XSS en outputs de datos de usuario
- Uso de funciones de deserializacion inseguras

#### Fase de QA/Staging (DAST)

```
Deploy to Staging -> DAST Pipeline:
                     1. OWASP ZAP baseline scan (passive)
                     2. OWASP ZAP active scan (targeted)
                     3. Nuclei templates (CVEs, misconfig)
                     4. Custom scripts para logica de negocio
                           |
                    Results -> DefectDojo (gestion de vulnerabilidades)
                                  |
                           Vulnerabilidades criticas/altas?
                              |                    |
                             YES                  NO
                              |                    |
                         Bloquear release      Aprobar deploy
```

**Escenarios criticos de DAST para el portal financiero:**
- Pruebas de IDOR en endpoints de actualizacion de datos
- Pruebas de CSRF en endpoints de transferencias
- Fuzzing de parametros de montos en transacciones
- Pruebas de upload de archivos maliciosos
- Verificacion de headers de seguridad
- Pruebas de autenticacion (brute force, session fixation)

#### Fase de Produccion (Continua)

- DAST programado semanal/mensual (scans ligeros, no intrusivos)
- Monitoreo continuo con Nuclei para nuevos CVEs
- Pen testing manual semestral (Burp Suite Pro) por equipo especializado

### 4.5 Recomendacion de Integracion

Para el portal financiero de XYZ, se recomienda un enfoque **combinado SAST + DAST + SCA (Software Composition Analysis)**:

1. **SAST en cada commit/PR:** Semgrep + SonarQube con quality gates bloqueantes
2. **SCA continuo:** Snyk o Dependabot para vulnerabilidades en dependencias
3. **DAST en staging:** OWASP ZAP automatizado en cada deploy a staging
4. **DAST periodico:** Burp Suite Pro manual mensual
5. **Gestion centralizada:** DefectDojo para consolidar hallazgos y tracking de remediacion

---

## Tarea 5: Analisis de Secrets Hardcodeados

### 5.1 Hallazgo

Durante un analisis SAST del codigo fuente del portal web, se identificaron **strings de conexion a base de datos y API keys hardcodeados** directamente en el codigo fuente.

### 5.2 Veredicto: RIESGO REAL Y CRITICO

**Este hallazgo NO es un falso positivo.** Se trata de un **riesgo real de seguridad de severidad CRITICA** que requiere remediacion inmediata.

### 5.3 Argumentacion Tecnica

#### Argumento 1: Exposicion de Credenciales por Acceso al Codigo

Cualquier persona con acceso al repositorio de codigo fuente (desarrolladores actuales, pasantes, contratistas, ex-empleados con acceso no revocado) obtiene **acceso directo e irrestricto** a la base de datos y APIs externas. Esto viola el principio de **minimo privilegio** ya que no todos los desarrolladores necesitan credenciales de produccion.

#### Argumento 2: Compromiso del Repositorio = Compromiso Total

Si el repositorio es comprometido (filtracion de GitHub/GitLab, laptop de desarrollador robada, ataque a la cadena de suministro del SCM), las credenciales quedan **inmediatamente expuestas**. En 2023, GitHub reporto que el secret scanning detecto mas de **12 millones de secrets** en repositorios publicos.

#### Argumento 3: Dificultad de Rotacion

Con credenciales hardcodeadas, la **rotacion de credenciales** requiere:
- Modificar el codigo fuente
- Pasar por el ciclo completo de CI/CD
- Redesplegar la aplicacion

Esto hace que la rotacion sea lenta y costosa, cuando deberia ser una operacion operativa rapida y rutinaria.

#### Argumento 4: Violacion del Principio de Separacion

El codigo fuente y las credenciales/configuracion son preocupaciones separadas. Mezclarlos viola:
- **12-Factor App** (Factor III: Config - almacenar config en el entorno)
- **Principio de separacion de responsabilidades** (Separation of Concerns)
- Impide tener diferentes credenciales por ambiente (dev/staging/prod) sin cambiar codigo

#### Argumento 5: Incumplimiento de Estandares y Regulaciones

| Estandar | Requisito Violado |
|----------|-------------------|
| **OWASP Top 10 - A07:2021** | Security Misconfiguration: credenciales por defecto o hardcodeadas |
| **CWE-798** | Use of Hard-coded Credentials |
| **CWE-259** | Use of Hard-coded Password |
| **PCI-DSS v4.0 Req. 6.2.4** | Software development processes protect against common vulnerabilities including hard-coded credentials |
| **PCI-DSS v4.0 Req. 2.2.2** | Vendor default accounts are managed (incluye credenciales hardcodeadas) |
| **NIST SP 800-53 IA-5** | Authenticator Management: proteger autenticadores contra disclosure no autorizada |
| **ISO 27001 A.8.4** | Access to source code: restringir acceso a credenciales |

### 5.4 Escenarios de Explotacion

1. **Insider threat:** Un desarrollador descontento copia las credenciales y accede a datos de produccion
2. **Supply chain attack:** Un paquete npm/pip malicioso lee archivos de configuracion del proyecto y exfiltra secrets
3. **Repository leak:** Accidentalmente se hace publico el repositorio (ha ocurrido en multiples organizaciones incluyendo Uber, Toyota, Samsung)
4. **Commit history:** Incluso si se eliminan los secrets del codigo actual, **permanecen en el historial de Git** y son recuperables

### 5.5 Recomendaciones de Remediacion

#### Inmediato (0-48 horas)

1. **Rotar todas las credenciales expuestas inmediatamente**
   - Cambiar connection strings de BD
   - Regenerar todas las API keys
   - Invalidar tokens activos
   - Verificar logs de acceso para detectar uso no autorizado

2. **Implementar variables de entorno** como solucion temporal
   ```
   # En lugar de:
   DB_CONNECTION = "postgresql://user:password@host:5432/db"

   # Usar:
   DB_CONNECTION = os.environ.get("DB_CONNECTION")
   ```

#### Corto plazo (1-2 semanas)

3. **Implementar un Secrets Manager**
   - **HashiCorp Vault** (on-premise/cloud, open source)
   - **AWS Secrets Manager** (si la infra es AWS)
   - **Azure Key Vault** (si la infra es Azure)
   - **GCP Secret Manager** (si la infra es GCP)

   Beneficios: rotacion automatica, audit logging, acceso granular por servicio/ambiente, cifrado en reposo.

4. **Limpiar el historial de Git**
   - Usar **BFG Repo-Cleaner** o `git filter-repo` para eliminar secrets de todo el historial
   - Force push del repositorio limpio
   - Notificar al equipo para re-clonar el repositorio
   ```bash
   # Ejemplo con BFG:
   bfg --replace-text passwords.txt repo.git
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive
   ```

#### Mediano plazo (1-4 semanas)

5. **Implementar secret scanning en CI/CD**

   | Herramienta | Tipo | Caracteristicas |
   |-------------|------|-----------------|
   | **GitLeaks** | Open Source | Pre-commit hook + CI/CD, regex customizable, rapido |
   | **TruffleHog** | Open Source | Deteccion por entropia + regex, analiza historial Git |
   | **GitHub Secret Scanning** | Integrado (GitHub) | Deteccion automatica, alertas a proveedores |
   | **GitLab Secret Detection** | Integrado (GitLab) | Incluido en CI/CD templates |
   | **detect-secrets** (Yelp) | Open Source | Baseline approach, bajo falsos positivos |

6. **Configurar pre-commit hooks** que bloqueen commits con secrets:
   ```yaml
   # .pre-commit-config.yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       hooks:
         - id: gitleaks
   ```

7. **Politica organizacional:** Documentar y comunicar la politica de gestion de secrets al equipo de desarrollo.

#### Largo plazo (1-3 meses)

8. **Rotacion automatica de credenciales** programada (cada 90 dias minimo)
9. **Auditorias periodicas** de repositorios para detectar secrets residuales
10. **Capacitacion** al equipo de desarrollo sobre gestion segura de secrets

---

# SECCION III: ARQUITECTURAS HIBRIDAS E INTEGRACIONES (Tareas 6-7)

---

## Tarea 6: Seguridad de Arquitectura Cloud + OnPremise

### 6.1 Arquitectura Actual

La arquitectura de la tienda virtual presenta un modelo hibrido Cloud + OnPremise:

```
                    USUARIOS
              ┌───────┬────────┐
              │Browser│App Movil│
              └───┬───┴────┬───┘
                  │        │
    ══════════════╧════════╧════════════════
                    CLOUD
    ┌─────────────────────────────────────┐
    │                                     │
    │   ┌──────────┐   ┌──────────────┐   │
    │   │ App Web  │   │    K8S       │   │
    │   │          │   │ Microservicios│  │
    │   └────┬─────┘   └──────┬───────┘   │
    │        │                │           │
    │        └────────┬───────┘           │
    │                 │                   │
    │        ┌────────▼────────┐          │
    │        │ BD Transaccional│          │
    │        └─────────────────┘          │
    └─────────────────┬───────────────────┘
                      │ (Conexion)
    ══════════════════╧═══════════════════
                   ON-PREMISE
    ┌─────────────────────────────────────┐
    │        ┌──────────────┐             │
    │        │Load Balancer │             │
    │        └──────┬───────┘             │
    │    ┌──────────┼──────────┐          │
    │    │          │          │          │
    │ ┌──▼───┐  ┌──▼────┐ ┌──▼─────┐    │
    │ │ API  │  │  API  │ │  API   │    │
    │ │Ventas│  │Compras│ │Billing │    │
    │ └──┬───┘  └──┬────┘ └──┬─────┘    │
    │    └──────────┼──────────┘          │
    │           ┌───▼───┐                │
    │           │  BD   │                │
    │           └───────┘                │
    └─────────────────────────────────────┘
```

### 6.2 Controles de Seguridad por Capa

#### Capa de Usuario (Browser / App Movil)

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| HTTPS obligatorio | Todas las comunicaciones cifradas con TLS 1.3 | ISO 27001 A.8.24 |
| HSTS (HTTP Strict Transport Security) | Header con max-age >= 1 ano, includeSubDomains, preload | OWASP ASVS 9.1 |
| Certificate Pinning (movil) | Verificacion del certificado del servidor en la app nativa | OWASP Mobile Top 10 M3 |
| Content Security Policy (CSP) | Politica estricta que previene XSS y data injection | OWASP ASVS 14.4 |
| Proteccion anti-tampering (movil) | Ofuscacion de codigo, deteccion de root/jailbreak | OWASP MASVS |

#### Capa Cloud - App Web

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| WAF (Web Application Firewall) | Reglas OWASP CRS, proteccion contra Top 10 | NIST SC-7 |
| Rate Limiting | Limitar requests por IP/usuario para prevenir abuso | OWASP ASVS 11.1 |
| Anti-DDoS | Proteccion volumetrica y de capa de aplicacion | NIST SC-5 |
| Input Validation | Validacion server-side de todos los parametros | OWASP ASVS 5.1 |
| Security Headers | CSP, X-Frame-Options, X-Content-Type-Options, etc. | OWASP Secure Headers |
| Bot Protection | Deteccion y mitigacion de trafico automatizado malicioso | - |

#### Capa Cloud - Kubernetes (K8S) Microservicios

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| Network Policies | Restringir comunicacion entre pods (deny-all por defecto) | CIS Kubernetes Benchmark 5.3 |
| Pod Security Standards | Enforced (restricted profile): no root, read-only fs, no privilege escalation | K8s Pod Security Standards |
| RBAC (K8s) | Role-Based Access Control para acceso al cluster y APIs | CIS Kubernetes Benchmark 5.1 |
| Image Scanning | Escaneo de vulnerabilidades en imagenes (Trivy, Grype) antes de deploy | NIST CM-3 |
| Service Mesh (Istio/Linkerd) | mTLS automatico entre servicios, observabilidad, circuit breaking | - |
| Admission Controllers | OPA/Gatekeeper para enforcing de politicas (no latest tag, no root, registries permitidos) | CIS Kubernetes Benchmark 5.6 |
| Secrets Management | External Secrets Operator con Vault/Cloud KMS, nunca secrets nativos de K8s sin cifrado | CIS Kubernetes Benchmark 5.4 |
| Resource Limits | CPU/memoria limits en todos los pods para prevenir resource abuse | CIS Kubernetes Benchmark 5.7 |
| Runtime Security | Falco para deteccion de comportamiento anomalo en runtime | - |

#### Capa Cloud - BD Transaccional

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| Cifrado en reposo | AES-256 (TDE o a nivel de columna para datos sensibles) | PCI-DSS 3.4 |
| Cifrado en transito | TLS para todas las conexiones a BD | PCI-DSS 4.1 |
| Acceso restringido por subnet | Solo pods de aplicacion en subnets autorizadas pueden conectar | NIST AC-3 |
| Backups cifrados | Backups automaticos cifrados con llaves gestionadas por KMS | ISO 27001 A.8.13 |
| Database Activity Monitoring | Monitoreo de queries anomalas, accesos fuera de horario | PCI-DSS 10.2 |
| Principle of Least Privilege | Cuentas de servicio con permisos minimos (solo SELECT/INSERT necesarios) | NIST AC-6 |

#### Capa de Integracion Cloud-OnPremise

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| VPN Site-to-Site | Conexion cifrada dedicada (IPSec VPN o Cloud Interconnect) | ISO 27001 A.8.20 |
| mTLS | Autenticacion mutua con certificados X.509 para la comunicacion | ISO 27001 A.8.24 |
| API Gateway | Punto centralizado de control en la frontera Cloud-OnPrem | NIST SC-7 |
| Firewall bidireccional | Reglas estrictas allow-list entre ambos ambientes | NIST SC-7 |
| IDS/IPS | Deteccion/prevencion de intrusiones en el enlace de interconexion | NIST SI-4 |
| Monitoring del enlace | Alertas por latencia, desconexiones, trafico anomalo | NIST CA-7 |

#### Capa OnPremise - Load Balancer

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| SSL/TLS Termination | Terminacion TLS con certificados validos y configuracion robusta | PCI-DSS 4.1 |
| Health Checks | Verificacion de salud de las APIs backend | - |
| Session Persistence Segura | Si se requiere sticky sessions, usar mecanismos seguros (no IP-based) | - |
| Access Logs | Logging de todas las conexiones para audit trail | ISO 27001 A.8.15 |
| DDoS Protection local | Rate limiting a nivel de LB | NIST SC-5 |

#### Capa OnPremise - APIs (Ventas, Compras, Billing)

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| Autenticacion OAuth 2.0 | Tokens de acceso con scopes limitados por API | OWASP API Security |
| Autorizacion con JWT | Claims verificados en cada request, firmados con RS256 | RFC 7519 |
| Rate Limiting por API | Limites diferenciados: Billing mas restrictivo que consultas | OWASP ASVS 11.1 |
| Input Validation | Validacion estricta de schema (JSON Schema validation) | OWASP ASVS 5.1 |
| Output Encoding | Prevencion de data leakage en respuestas | OWASP ASVS 5.3 |
| API Versioning | Versionamiento para gestion de cambios sin romper integraciones | - |
| Error Handling seguro | Mensajes de error genericos, sin stack traces ni datos internos | OWASP ASVS 7.4 |

#### Capa OnPremise - BD

| Control | Descripcion | Referencia |
|---------|-------------|------------|
| Cifrado en reposo | AES-256 TDE para toda la base de datos | PCI-DSS 3.4 |
| Acceso por minimo privilegio | Cuentas de servicio separadas por API, solo permisos necesarios | NIST AC-6 |
| Audit Logging | Registro de todas las operaciones DDL/DML criticas | PCI-DSS 10.2 |
| Network Isolation | BD solo accesible desde la red de APIs (no desde internet) | NIST SC-7 |
| Backup y DR | Backups cifrados, pruebas de restauracion trimestrales, RPO/RTO definidos | ISO 27001 A.8.13 |
| Patch Management | Actualizaciones de seguridad aplicadas dentro de SLA definido | NIST SI-2 |

### 6.3 Problemas Identificados y Mejoras Propuestas

| # | Problema Identificado | Riesgo | Mejora Propuesta | Prioridad |
|---|----------------------|--------|------------------|-----------|
| 1 | **Falta WAF** antes de la App Web en Cloud | Exposicion directa a ataques OWASP Top 10 | Implementar WAF (Cloud Armor, AWS WAF, Cloudflare) con reglas OWASP CRS frente a la App Web | **CRITICA** |
| 2 | **Falta API Gateway** en Cloud antes de los microservicios K8S | Sin control centralizado de autenticacion, rate limiting ni validacion | Implementar API Gateway (Kong, Apigee, AWS API Gateway) como punto de entrada a microservicios | **CRITICA** |
| 3 | **Conexion Cloud-OnPrem no especificada** (potencialmente via internet publico) | Interceptacion de datos en transito, MitM | Establecer VPN Site-to-Site (IPSec) o Cloud Interconnect dedicado. Nunca internet publico | **CRITICA** |
| 4 | **Falta CDN** para contenido estatico | Mayor superficie de ataque DDoS, latencia | Implementar CDN (CloudFlare, CloudFront) para contenido estatico + capa anti-DDoS | **ALTA** |
| 5 | **Falta SIEM/monitoreo centralizado** entre Cloud y OnPrem | Sin visibilidad unificada de incidentes, imposible correlacionar eventos | Implementar SIEM centralizado (Splunk, ELK, Microsoft Sentinel) con agents en ambos ambientes | **ALTA** |
| 6 | **Falta segmentacion de red visible** | Sin aislamiento entre componentes, movimiento lateral facilitado | Definir subnets privadas para BD (Cloud y OnPrem), Network Policies en K8S, VLANs en OnPrem | **ALTA** |
| 7 | **Falta IDS/IPS** en la frontera Cloud-OnPrem | Intrusion no detectada entre ambientes | Implementar IDS/IPS (Suricata, Snort, Cloud IDS) en el punto de interconexion | **ALTA** |
| 8 | **Falta mecanismo anti-DDoS** explicito | Disponibilidad del servicio comprometida | Proteccion DDoS a nivel de CDN/WAF y rate limiting en Load Balancers | **ALTA** |
| 9 | **Falta gestion centralizada de secretos** | Secrets potencialmente hardcodeados o dispersos | Vault centralizado (HashiCorp Vault) accesible desde ambos ambientes | **MEDIA** |
| 10 | **Falta estrategia de DR/BCP** multi-ambiente | Recuperacion compleja ante desastre | Plan de DR documentado que cubra failover Cloud<->OnPrem, backups cruzados | **MEDIA** |

### 6.4 Arquitectura Mejorada (Propuesta)

```
                    USUARIOS
              ┌───────┬────────┐
              │Browser│App Movil│
              └───┬───┴────┬───┘
                  │  HTTPS  │
         ┌────────▼────────▼────────┐
         │   CDN + Anti-DDoS        │  <-- NUEVO
         └────────────┬─────────────┘
         ┌────────────▼─────────────┐
         │      WAF (OWASP CRS)     │  <-- NUEVO
         └────────────┬─────────────┘
    ══════════════════╧═══════════════════
                    CLOUD
    ┌─────────────────────────────────────┐
    │   ┌──────────────────┐              │
    │   │   API Gateway    │  <-- NUEVO   │
    │   └────────┬─────────┘              │
    │   ┌────────▼─────────┐              │
    │   │    App Web       │              │
    │   └────────┬─────────┘              │
    │   ┌────────▼─────────┐              │
    │   │K8S Microservicios│              │
    │   │(Network Policies,│              │
    │   │ mTLS, RBAC, PSS) │              │
    │   └────────┬─────────┘              │
    │   ┌────────▼─────────┐              │
    │   │BD Transaccional  │              │
    │   │(Subnet privada,  │              │
    │   │ cifrado, DAM)    │              │
    │   └──────────────────┘              │
    └─────────────┬───────────────────────┘
                  │
         ┌────────▼────────┐
         │  VPN/Interconnect│  <-- NUEVO
         │  + IDS/IPS       │  <-- NUEVO
         └────────┬─────────┘
    ══════════════╧═══════════════════════
                 ON-PREMISE
    ┌─────────────────────────────────────┐
    │   ┌──────────────┐                  │
    │   │Load Balancer │                  │
    │   │(SSL term, HC)│                  │
    │   └──────┬───────┘                  │
    │    ┌─────┼─────────┐                │
    │ ┌──▼──┐┌─▼───┐┌───▼───┐            │
    │ │ API ││ API ││  API  │            │
    │ │Venta││Compr││Billing│            │
    │ └──┬──┘└──┬──┘└───┬───┘            │
    │    └──────┼────────┘                │
    │       ┌───▼───┐                    │
    │       │  BD   │ (Subnet privada)   │
    │       └───────┘                    │
    └─────────────────────────────────────┘

    ┌─────────────────────────────────────┐
    │     SIEM CENTRALIZADO  <-- NUEVO    │
    │  (Cloud + OnPrem logs aggregation)  │
    └─────────────────────────────────────┘
```

---

## Tarea 7: Seguridad en Integracion API con Proveedor 123

### 7.1 Arquitectura Actual Propuesta

```
    PROVEEDOR 123                           XYZ
    ┌─────────────────┐                    ┌──────────────────────────┐
    │                 │                    │                          │
    │   ┌─────┐      │                    │  ┌───────┐  ┌─────────┐ │
    │   │ BD  │      │                    │  │ API 1 │  │  Load   │ │
    │   └──┬──┘      │    Conexion        │  └───┬───┘  │Balancer │ │
    │      │         │◄──────────────────►│      │      └────┬────┘ │
    │   ┌──▼──────┐  │                    │  ┌───▼───┐       │      │
    │   │Firewall │  │                    │  │ API 2 │───────┘      │
    │   └─────────┘  │                    │  └───────┘              │
    │                 │                    │                          │
    └─────────────────┘                    └──────────────────────────┘
```

### 7.2 Problemas Identificados en la Arquitectura

| # | Problema | Riesgo Asociado | Severidad |
|---|----------|-----------------|-----------|
| 1 | **No se evidencia cifrado** en la conexion entre proveedor y XYZ | Man-in-the-Middle, interceptacion de datos sensibles en transito | **CRITICA** |
| 2 | **Falta API Gateway** del lado de XYZ | Sin punto centralizado de control, validacion ni rate limiting para trafico entrante del proveedor | **CRITICA** |
| 3 | **Falta autenticacion visible** (ni OAuth2, ni API keys, ni certificados mutuos) | Acceso no autenticado a APIs de XYZ, impersonacion del proveedor | **CRITICA** |
| 4 | **Falta WAF** del lado de XYZ antes del Load Balancer | APIs expuestas a inyeccion, payloads maliciosos desde el proveedor | **ALTA** |
| 5 | **Proveedor con acceso a datos personales** sin evaluacion de cumplimiento | Violacion de Ley 1581 de 2012 (Habeas Data Colombia), GDPR si aplica | **ALTA** |
| 6 | **Solo firewall del lado del proveedor**, no del lado de XYZ | Falta defensa perimetral propia; XYZ depende de la seguridad del proveedor | **ALTA** |
| 7 | **Falta monitoreo y logging** de la integracion | Imposible detectar anomalias, abusos o brechas en la comunicacion API | **ALTA** |
| 8 | **Sin rate limiting** visible en el lado de XYZ | Proveedor podria (accidental o intencionalmente) generar DoS en APIs de XYZ | **MEDIA** |

### 7.3 Controles de Seguridad Recomendados

#### 7.3.1 Autenticacion y Autorizacion

| Control | Detalle |
|---------|---------|
| **mTLS (Mutual TLS)** | Autenticacion mutua con certificados X.509. Ambas partes (XYZ y Proveedor 123) presentan certificados. Garantiza identidad bidireccional. CA interna o CA publica de confianza. |
| **OAuth 2.0 con Client Credentials** | Flujo machine-to-machine con scopes limitados. El proveedor recibe tokens de acceso con permisos minimos para las APIs que necesita. Tokens con expiracion corta (15-30 min). |
| **API Keys como capa adicional** | API key unica por proveedor para identificacion y rate limiting. No como unico mecanismo de autenticacion. |
| **IP Whitelisting** | Solo permitir conexiones desde rangos de IP conocidos del Proveedor 123. Implementar en firewall y a nivel de API Gateway. |

#### 7.3.2 Infraestructura de Seguridad

| Control | Detalle |
|---------|---------|
| **API Gateway (del lado de XYZ)** | Kong, Apigee, o AWS API Gateway. Funciones: autenticacion, rate limiting (ej. 100 req/min por proveedor), throttling, validacion de schema JSON/XML, transformacion de payloads, logging centralizado. |
| **WAF antes del Load Balancer** | Web Application Firewall con reglas especificas para APIs: validacion de Content-Type, tamano maximo de payload, deteccion de payloads maliciosos. |
| **Firewall del lado de XYZ** | Reglas estrictas: solo permitir trafico desde IPs del proveedor, solo puertos necesarios (443), deny-all por defecto. |
| **Cifrado TLS 1.3** | Minimo TLS 1.3 para toda la comunicacion. Cipher suites fuertes (AEAD). Perfect Forward Secrecy (PFS) obligatorio. |

#### 7.3.3 Proteccion de Datos

| Control | Detalle |
|---------|---------|
| **Data Minimization** | Solo compartir datos estrictamente necesarios para la funcionalidad. Revisar cada campo de cada API: si no es esencial, no se comparte. |
| **Enmascaramiento de datos sensibles** | Enmascarar PII cuando sea posible (ej. solo ultimos 4 digitos de documento). |
| **Clasificacion de datos** | Documentar que datos se comparten, su clasificacion y el proposito (base legal de Ley 1581). |
| **Cifrado a nivel de campo** | Para datos especialmente sensibles, cifrado adicional a nivel de payload (JWE - JSON Web Encryption). |

#### 7.3.4 Monitoreo y Operacion

| Control | Detalle |
|---------|---------|
| **Logging de todas las llamadas API** | Registrar: timestamp, endpoint, IP origen, usuario/API key, request/response (sin datos sensibles), status code, latencia. |
| **Alertas de anomalias** | Alertas para: volumen inusual de requests, errores masivos (4xx/5xx), acceso fuera de horario acordado, cambios en patrones de uso. |
| **Dashboard de monitoreo** | Visibilidad en tiempo real del estado de la integracion, SLAs, errores. |
| **Audit Trail inmutable** | Registro inmutable de todas las transacciones para propositos de auditoria y forense. |

### 7.4 Evaluacion del Proveedor 123

#### 7.4.1 Due Diligence Inicial

Antes de establecer la integracion, XYZ debe realizar una evaluacion integral del Proveedor 123:

| Area de Evaluacion | Requisitos |
|--------------------|------------|
| **Certificaciones de seguridad** | Solicitar y verificar: ISO 27001 (vigente), SOC 2 Type II (ultimo reporte), PCI-DSS si maneja datos de tarjeta |
| **Evaluacion de riesgo de terceros (TPRM)** | Realizar Third Party Risk Assessment formal usando cuestionario estandarizado (SIG Questionnaire, CAIQ de CSA) |
| **Pruebas de seguridad del proveedor** | Solicitar ultimo reporte de pentest, resultados de escaneo de vulnerabilidades, programa de vulnerability disclosure |
| **Arquitectura de seguridad** | Revisar la arquitectura de seguridad del proveedor: cifrado, gestion de accesos, segmentacion, monitoreo |
| **Gestion de incidentes** | Verificar que el proveedor tenga un plan de respuesta a incidentes documentado y probado |
| **Continuidad de negocio** | Revisar BCP/DRP del proveedor, RPO/RTO, redundancia |

#### 7.4.2 Clausulas Contractuales Obligatorias

| Clausula | Contenido |
|----------|-----------|
| **Data Processing Agreement (DPA)** | Acuerdo de procesamiento de datos conforme a Ley 1581 de 2012 (y GDPR si aplica). Definir roles (responsable/encargado), finalidad, datos tratados, plazo, medidas de seguridad. |
| **Derecho a auditoria** | XYZ tiene derecho a auditar (directamente o via tercero) las practicas de seguridad del proveedor. Minimo 1 vez al ano. |
| **Notificacion de incidentes** | Obligacion de notificar brechas de seguridad en un plazo maximo de 24-48 horas. Incluir alcance, datos afectados, medidas de contencion. |
| **SLA de seguridad** | Niveles de servicio para: disponibilidad de APIs, tiempo de respuesta a incidentes, tiempo de aplicacion de parches criticos. |
| **Clausula de terminacion** | Procedimiento de terminacion que incluya: eliminacion/devolucion de datos de XYZ, periodo de transicion, certificacion de destruccion. |
| **Responsabilidad por brechas** | Definir responsabilidades y compensaciones en caso de brecha de seguridad atribuible al proveedor. |
| **Subcontratistas** | El proveedor no puede subcontratar el procesamiento de datos de XYZ sin autorizacion previa y escrita. |

#### 7.4.3 Monitoreo Continuo del Proveedor

- **Evaluaciones de riesgo periodicas:** Anuales como minimo, mas frecuentes si el proveedor maneja datos criticos
- **Revision de certificaciones:** Verificar vigencia de ISO 27001 y SOC 2 anualmente
- **Scorecard de seguridad:** Utilizar servicios como BitSight, SecurityScorecard o RiskRecon para monitoreo continuo de la postura de seguridad del proveedor
- **Revision de SLAs:** Monitoreo mensual del cumplimiento de SLAs acordados
- **Ejercicios de respuesta a incidentes:** Simulacros conjuntos de incidentes al menos una vez al ano

### 7.5 Arquitectura Mejorada Propuesta

```
    PROVEEDOR 123                             XYZ
    ┌─────────────────┐                      ┌───────────────────────────────────┐
    │                 │                      │                                   │
    │   ┌─────┐      │                      │  ┌──────────┐                    │
    │   │ BD  │      │    mTLS (TLS 1.3)    │  │ Firewall │ <-- NUEVO         │
    │   └──┬──┘      │    + VPN/Dedicated   │  └────┬─────┘                    │
    │      │         │◄────────────────────►│  ┌────▼─────┐                    │
    │   ┌──▼──────┐  │    IP Whitelisting   │  │   WAF    │ <-- NUEVO         │
    │   │Firewall │  │                      │  └────┬─────┘                    │
    │   └─────────┘  │                      │  ┌────▼───────────┐              │
    │                 │                      │  │  API Gateway   │ <-- NUEVO   │
    │                 │                      │  │(OAuth2, Rate   │              │
    │                 │                      │  │ Limit, Schema) │              │
    │                 │                      │  └────┬───────────┘              │
    │                 │                      │  ┌────▼──────┐  ┌─────────┐     │
    │                 │                      │  │  API 1    │  │  Load   │     │
    │                 │                      │  └────┬──────┘  │Balancer │     │
    │                 │                      │  ┌────▼──────┐  └────┬────┘     │
    │                 │                      │  │  API 2    │───────┘          │
    │                 │                      │  └───────────┘                   │
    │                 │                      │                                   │
    │                 │                      │  ┌───────────────┐               │
    │                 │                      │  │SIEM/Monitoring│ <-- NUEVO    │
    │                 │                      │  └───────────────┘               │
    └─────────────────┘                      └───────────────────────────────────┘
```

### 7.6 Marco Legal Aplicable (Colombia)

| Normativa | Aplicabilidad |
|-----------|--------------|
| **Ley 1581 de 2012** | Proteccion de datos personales. Obligaciones del responsable y encargado del tratamiento. |
| **Decreto 1377 de 2013** | Reglamentacion de Ley 1581. Requisitos para transferencias de datos a terceros. |
| **Circular Externa 007 de 2018 (SFC)** | Requisitos de ciberseguridad para entidades supervisadas por la Superintendencia Financiera. |
| **Circular Externa 042 de 2012 (SFC)** | Requisitos minimos de seguridad para canales electronicos de entidades financieras. |
| **PCI-DSS v4.0** | Si la integracion involucra datos de tarjeta, ambas partes deben cumplir PCI-DSS. |

---

# SECTION IV: SECURITY CONCEPTS AND BEST PRACTICES (Tasks 8-12)

*Note: Tasks 8 through 12 are answered in English as per the original assessment requirements.*

---

## Task 8: DevSecOps

### 8.1 What is DevSecOps?

**DevSecOps** (Development, Security, and Operations) is the practice of **integrating security into every phase of the Software Development Life Cycle (SDLC)**, rather than treating it as a gate at the end. It represents a cultural shift where security becomes a **shared responsibility** among developers, security engineers, and operations teams.

The core principle is **"Shift Left"**: moving security testing and validation as early as possible in the development process, where vulnerabilities are cheapest and easiest to fix.

### 8.2 How DevSecOps Improves Cybersecurity

| Benefit | Description |
|---------|-------------|
| **Early Detection** | Vulnerabilities are caught during coding, not after deployment. Fixing a vulnerability in development is **6-100x cheaper** than fixing it in production (NIST/IBM Systems Sciences Institute). |
| **Continuous Security** | Security is not a one-time event but a continuous process embedded in every commit, build, and deploy. |
| **Reduced Attack Surface** | Automated scanning catches common vulnerabilities before they reach production, significantly reducing the attack surface. |
| **Faster Remediation** | Developers get immediate feedback on security issues in their IDE or PR, enabling quick fixes while the code is fresh in their mind. |
| **Compliance as Code** | Security policies and compliance requirements are codified and automatically enforced, ensuring consistent adherence to standards. |
| **Cultural Change** | Developers become security-aware, creating a culture where security is everyone's responsibility, not just the security team's. |
| **Reduced Risk** | By addressing security throughout the SDLC, the overall risk posture of the organization improves significantly. |

### 8.3 DevSecOps Pipeline: Phases, Practices, and Tools

#### Phase 1: Plan

**Objective:** Identify security requirements and threat models before writing code.

| Practice | Tools | Description |
|----------|-------|-------------|
| Threat Modeling | Microsoft Threat Modeling Tool, OWASP Threat Dragon, IriusRisk | Identify potential threats using STRIDE methodology. Analyze data flows, trust boundaries, and attack vectors for the financial portal. |
| Security Requirements | OWASP ASVS, NIST SP 800-53 | Define security requirements based on the application's risk profile. For XYZ: PCI-DSS requirements for payment features, data protection for PII. |
| Security User Stories | Jira, Azure DevOps | Create security-specific user stories: "As a security engineer, I want all API inputs validated server-side so that injection attacks are prevented." |

#### Phase 2: Code

**Objective:** Prevent security issues from being introduced during development.

| Practice | Tools | Description |
|----------|-------|-------------|
| IDE Security Plugins | SonarLint, Snyk IDE Plugin, Semgrep VSCode | Real-time security feedback as developers write code. Highlights vulnerable patterns before commit. |
| Pre-commit Hooks | GitLeaks, TruffleHog, detect-secrets | Prevent secrets (API keys, passwords, connection strings) from being committed to the repository. |
| Secure Coding Standards | OWASP Secure Coding Practices | Team-wide standards for input validation, output encoding, authentication, and error handling. |
| Peer Code Review | GitHub PRs, GitLab MRs | Security-focused code review checklist for pull requests. |

#### Phase 3: Build

**Objective:** Automatically analyze code and dependencies for vulnerabilities during the build process.

| Practice | Tools | Description |
|----------|-------|-------------|
| SAST (Static Analysis) | SonarQube, Semgrep, Checkmarx, Fortify | Analyze source code for security vulnerabilities without executing it. Integrated into CI pipeline. |
| SCA (Software Composition Analysis) | Snyk, Dependabot, OWASP Dependency-Check, Renovate | Scan third-party libraries and dependencies for known vulnerabilities (CVEs). Critical for supply chain security. |
| License Compliance | FOSSA, Snyk License | Ensure open-source licenses are compatible with the project's requirements. |
| Build Hardening | Reproducible builds, signed artifacts | Ensure build integrity and prevent tampering. |

**Example CI Pipeline (GitHub Actions):**

```yaml
security-scan:
  steps:
    - name: SAST - Semgrep
      run: semgrep ci --config=p/owasp-top-ten
    - name: SCA - Snyk
      run: snyk test --severity-threshold=high
    - name: Secret Scan - GitLeaks
      run: gitleaks detect --source=. --verbose
    - name: Quality Gate - SonarQube
      run: sonar-scanner
```

#### Phase 4: Test

**Objective:** Validate application security through dynamic testing and security-specific test cases.

| Practice | Tools | Description |
|----------|-------|-------------|
| DAST (Dynamic Analysis) | OWASP ZAP, Burp Suite, Nuclei | Test the running application for exploitable vulnerabilities. Automated scans in staging environment. |
| IAST (Interactive Analysis) | Contrast Security, Seeker | Combines SAST and DAST approaches by instrumenting the application during testing. Lower false positives. |
| Security Unit Tests | pytest, JUnit (with security assertions) | Automated tests for authentication bypass, authorization checks, input validation, and business logic flaws. |
| Penetration Testing | Burp Suite Pro, manual testing | Periodic manual security testing by experienced pentesters for business logic and complex vulnerabilities. |

#### Phase 5: Release

**Objective:** Ensure artifacts are secure and compliant before deployment.

| Practice | Tools | Description |
|----------|-------|-------------|
| Container Image Scanning | Trivy, Grype, Anchore | Scan container images for OS and library vulnerabilities before pushing to registry. |
| IaC Security Scanning | Checkov, tfsec, KICS | Analyze Infrastructure as Code (Terraform, CloudFormation, K8s manifests) for misconfigurations. |
| Image Signing | Cosign (Sigstore), Notary | Cryptographically sign container images to guarantee integrity and provenance. |
| Compliance Checks | Open Policy Agent (OPA) | Validate that release artifacts meet organizational security policies. |

#### Phase 6: Deploy

**Objective:** Enforce security policies during the deployment process.

| Practice | Tools | Description |
|----------|-------|-------------|
| Kubernetes Admission Controllers | OPA/Gatekeeper, Kyverno | Enforce policies at deploy time: no privileged containers, no latest tags, required resource limits, mandatory labels. |
| Signed Image Verification | Cosign + Admission Controller | Only allow deployment of cryptographically signed images from trusted registries. |
| Secrets Injection | HashiCorp Vault, AWS Secrets Manager, External Secrets Operator | Inject secrets at runtime, never baked into images or stored in environment variables. |
| Immutable Infrastructure | Terraform, Pulumi | Infrastructure changes only through code, no manual modifications. Drift detection enabled. |

#### Phase 7: Operate

**Objective:** Maintain security posture in the production environment.

| Practice | Tools | Description |
|----------|-------|-------------|
| Runtime Security Monitoring | Falco, Sysdig Secure | Detect anomalous behavior at runtime: unexpected process execution, file access, network connections. |
| SIEM & Log Aggregation | Splunk, ELK Stack, Microsoft Sentinel | Centralized security logging, correlation, and alerting. |
| Incident Response | PagerDuty, Opsgenie, IR playbooks | Automated alerting and structured incident response procedures. |
| Patch Management | Renovate, Dependabot, automated redeployment | Continuous patching of OS, runtime, and application dependencies. |

#### Phase 8: Monitor

**Objective:** Continuously assess and improve the security posture.

| Practice | Tools | Description |
|----------|-------|-------------|
| Vulnerability Management | DefectDojo, Dojo, Jira | Aggregate findings from all security tools, track remediation SLAs, measure trends. |
| Compliance Monitoring | Prowler (AWS), ScoutSuite, cloud-native tools | Continuous compliance checking against CIS Benchmarks, PCI-DSS, SOC 2. |
| Security Metrics & KPIs | Grafana dashboards, custom reporting | Track: Mean Time to Remediate (MTTR), vulnerability density, escape rate (vulns reaching production). |
| Threat Intelligence | MITRE ATT&CK, threat feeds | Stay informed about emerging threats relevant to the technology stack. |

### 8.4 DevSecOps Maturity Model

| Level | Characteristics |
|-------|----------------|
| **Level 1: Initial** | Security is manual, ad-hoc. Pen tests only before major releases. |
| **Level 2: Managed** | Basic SAST/DAST in CI/CD. Secret scanning. Some automation. |
| **Level 3: Defined** | Full pipeline with SAST, DAST, SCA, IaC scanning. Quality gates enforced. Security training for developers. |
| **Level 4: Measured** | Metrics-driven. MTTR targets. Vulnerability density tracking. Compliance as code. |
| **Level 5: Optimized** | Continuous improvement. Threat modeling integrated. Runtime security. Automated incident response. Chaos engineering. |

For XYZ's financial portal, the recommendation is to target **Level 3** within 6 months and **Level 4** within 12 months.

---

## Task 9: Data Masking vs Data Encryption

### 9.1 Definitions

**Data Masking** is the process of replacing sensitive data with **fictitious but realistic-looking data** that maintains the format and structure of the original. The masked data is usable for testing, analytics, and reporting without exposing actual sensitive information.

**Data Encryption** is the process of transforming data into an **unreadable ciphertext** using cryptographic algorithms and keys. The original data can only be recovered (decrypted) by authorized parties who possess the correct decryption key.

### 9.2 Detailed Comparison

| Aspect | Data Masking | Data Encryption |
|--------|-------------|-----------------|
| **Definition** | Replaces sensitive data with fictitious but realistic values | Transforms data using cryptographic algorithms into ciphertext |
| **Reversibility** | **Irreversible** (static masking) or pseudo-reversible (dynamic masking with lookup table) | **Fully reversible** with the correct decryption key |
| **Primary Use Case** | Development/testing environments, reports, analytics, data sharing with third parties | Protecting data at rest (storage) and in transit (communication) |
| **Data Utility** | Masked data retains format and referential integrity (useful for testing) | Encrypted data is unusable without decryption (not suitable for testing) |
| **Performance Impact** | Low (applied once for static; moderate for dynamic) | Moderate to high (encryption/decryption overhead on every access) |
| **Key Management** | No cryptographic keys required | Requires robust key management infrastructure (KMS/HSM) |
| **Compliance** | Satisfies data minimization requirements (GDPR Art. 5, Ley 1581) | Satisfies data protection requirements (PCI-DSS Req. 3.4, GDPR Art. 32) |
| **Data at Rest** | Not a protection mechanism for production data | Primary mechanism for protecting stored sensitive data |
| **Data in Transit** | Not applicable | Essential for protecting data during transmission (TLS) |

### 9.3 Types of Data Masking

| Type | Description | Use Case |
|------|-------------|----------|
| **Static Data Masking (SDM)** | Creates a permanently masked copy of the database. Original data is irreversibly replaced. | Populating dev/test databases with realistic but non-sensitive data. |
| **Dynamic Data Masking (DDM)** | Masks data on-the-fly at query time based on user permissions. Original data remains intact in storage. | Restricting access to sensitive fields for certain user roles (e.g., support agents see masked credit card numbers). |
| **On-the-Fly Masking** | Masks data during ETL (Extract, Transform, Load) processes as it moves between environments. | Transferring production data to staging with masking applied during the transfer. |

### 9.4 Types of Data Encryption

| Type | Description | Algorithms | Use Case |
|------|-------------|------------|----------|
| **Symmetric Encryption** | Same key for encryption and decryption. Fast. | AES-256, ChaCha20 | Encrypting databases, files, disk volumes |
| **Asymmetric Encryption** | Public key encrypts, private key decrypts. Slower. | RSA-2048/4096, ECDSA | Key exchange, digital signatures, TLS handshake |
| **Hashing (one-way)** | Irreversible transformation. Not encryption per se. | bcrypt, Argon2, SHA-256 | Password storage, integrity verification |
| **Tokenization** | Replaces data with a random token; original stored in secure vault. | N/A (vault-based) | Credit card numbers (PCI-DSS), PII in transit |

### 9.5 Practical Examples for XYZ's Financial Portal

#### Example 1: Credit Card Numbers

| Technique | Original Data | Result |
|-----------|--------------|--------|
| **Static Masking** | 4532-7891-2345-6789 | 4532-XXXX-XXXX-6789 (only first 6, last 4 visible) |
| **Dynamic Masking** | 4532-7891-2345-6789 | Admin sees full number; support agent sees 4532-****-****-6789 |
| **AES-256 Encryption** | 4532-7891-2345-6789 | aG4kL9mN2pQ8rS1tU7vW3xY5zA... (ciphertext) |
| **Tokenization** | 4532-7891-2345-6789 | tok_8f3a2b1c9d4e (random token; original in PCI vault) |

#### Example 2: Email Addresses

| Technique | Original Data | Result |
|-----------|--------------|--------|
| **Static Masking** | juan.perez@gmail.com | j\*\*\*\*\*\*\*z@gmail.com |
| **Dynamic Masking** | juan.perez@gmail.com | Shown based on user role permissions |
| **RSA Encryption** | juan.perez@gmail.com | Encrypted blob stored in database |
| **Format-Preserving Encryption** | juan.perez@gmail.com | kfmq.txnbc@gmail.com (same format, encrypted) |

#### Example 3: Customer Names

| Technique | Original Data | Result |
|-----------|--------------|--------|
| **Static Masking** | Juan Carlos Perez | "Maria Lopez" (realistic fake data via Faker library) |
| **Substitution Masking** | Juan Carlos Perez | "Cliente_A7B3" (pseudonymized) |
| **AES-256 Encryption** | Juan Carlos Perez | 0x7A3F...encrypted blob |

#### Example 4: Transaction Amounts

| Technique | Original Data | Result |
|-----------|--------------|--------|
| **Masking (variance)** | $15,000.00 | $14,832.47 (realistic but altered amount for testing) |
| **Encryption** | $15,000.00 | Encrypted and stored; decrypted only for authorized operations |

### 9.6 When to Use Each

| Scenario | Recommended Approach | Justification |
|----------|---------------------|---------------|
| Production database storage | **Encryption** (AES-256 TDE) | Protect real data at rest; needs to be reversible for operations |
| Dev/test environments | **Static Data Masking** | Developers need realistic data but must NOT access real PII |
| Customer support portal | **Dynamic Data Masking** | Support agents see partial data; supervisors see full data based on role |
| Credit card processing | **Tokenization** + Encryption | PCI-DSS requires tokenization; encryption for storage |
| Data shared with Proveedor 123 | **Masking** + Encryption in transit | Minimize data shared; encrypt during transmission |
| Backup files | **Encryption** (AES-256) | Backups must be encrypted; masking would destroy data utility for recovery |
| Analytics and reporting | **Masking** or **Anonymization** | Reports don't need real PII; comply with data minimization |

### 9.7 Key Takeaway

**Data masking and data encryption are complementary, not competing techniques.** A robust data protection strategy for XYZ's financial portal should use both:

- **Encryption** to protect production data at rest and in transit
- **Masking** to protect non-production environments and limit data exposure
- **Tokenization** (a form of masking with vault) for PCI-DSS compliance on credit card data

---

## Task 10: Shared Responsibility Model

### 10.1 Overview

The **Shared Responsibility Model** defines the division of security responsibilities between the **Cloud Service Provider (CSP)** and the **Customer** across different cloud service models. Understanding this model is critical for ensuring no security gaps exist due to unclear ownership.

The general principle is: **"Security OF the cloud" is the provider's responsibility; "Security IN the cloud" is the customer's responsibility.**

### 10.2 Responsibility Matrix

| Component | IaaS | PaaS | CaaS | SaaS |
|-----------|------|------|------|------|
| **Data Classification & Protection** | Customer | Customer | Customer | Customer |
| **User Access & Identity Management** | Customer | Customer | Customer | Customer |
| **Application Code** | Customer | Customer | Customer | Provider |
| **Application Configuration** | Customer | Customer | Customer | Shared |
| **Runtime Environment** | Customer | Provider | Shared | Provider |
| **Containers / Orchestration** | Customer | Provider | Provider | Provider |
| **Operating System** | Customer | Provider | Provider | Provider |
| **Middleware** | Customer | Provider | Provider | Provider |
| **Virtualization / Hypervisor** | Provider | Provider | Provider | Provider |
| **Network Infrastructure** | Provider | Provider | Provider | Provider |
| **Physical Storage** | Provider | Provider | Provider | Provider |
| **Physical Datacenter** | Provider | Provider | Provider | Provider |

### 10.3 Detailed Breakdown by Service Model

#### IaaS (Infrastructure as a Service)

**Examples:** AWS EC2, Azure Virtual Machines, Google Compute Engine

**Provider Responsibilities:**
- Physical datacenter security (access controls, environmental controls, power, cooling)
- Physical network infrastructure (routers, switches, cabling)
- Hypervisor and virtualization platform security
- Hardware maintenance and lifecycle management
- Global network backbone and DDoS protection at infrastructure level

**Customer Responsibilities:**
- Operating system installation, patching, and hardening
- Application deployment, configuration, and security
- Network configuration (security groups, firewalls, VPNs)
- Data encryption (at rest and in transit)
- Identity and access management (IAM policies, MFA)
- Monitoring, logging, and incident response
- Backup and disaster recovery strategy
- Compliance validation for workloads

#### PaaS (Platform as a Service)

**Examples:** AWS Elastic Beanstalk, Azure App Service, Google App Engine, Heroku

**Provider Responsibilities:**
- Everything in IaaS provider scope, plus:
- Operating system management and patching
- Runtime environment (JVM, Node.js, Python runtime) maintenance
- Middleware and platform components
- Platform-level scaling and availability

**Customer Responsibilities:**
- Application code security (secure coding practices, SAST)
- Application-level configuration (environment variables, feature flags)
- Data classification, protection, and encryption
- User identity and access management
- Application-level monitoring and logging
- API security and input validation
- Third-party library and dependency management (SCA)

#### CaaS (Container as a Service)

**Examples:** AWS EKS, Azure AKS, Google GKE, Red Hat OpenShift

**Provider Responsibilities:**
- Everything in IaaS provider scope, plus:
- Kubernetes control plane management (API server, etcd, scheduler, controller manager)
- Control plane availability and patching
- Node OS for managed node pools (in fully managed services)
- Container runtime patching (containerd, CRI-O)
- Network plugin (CNI) management

**Shared Responsibilities (Provider + Customer):**
- Runtime security: Provider secures the container runtime; Customer configures Pod Security Standards, seccomp profiles, and AppArmor
- Networking: Provider provides network infrastructure; Customer defines Network Policies and service mesh configuration

**Customer Responsibilities:**
- Container image security (base image selection, vulnerability scanning, no root)
- Application code and configuration inside containers
- Kubernetes workload configuration (Deployments, RBAC, resource limits)
- Network Policies (micro-segmentation between pods)
- Secrets management (external secrets, not native K8s secrets without encryption)
- Data protection and encryption
- Monitoring and logging (application-level)
- CI/CD pipeline security

#### SaaS (Software as a Service)

**Examples:** Salesforce, Microsoft 365, Google Workspace, ServiceNow

**Provider Responsibilities:**
- Entire technology stack (infrastructure through application)
- Application security and patching
- Platform availability and performance
- Default security features (encryption, audit logging)
- Compliance certifications (SOC 2, ISO 27001)
- Incident response for platform-level incidents

**Customer Responsibilities:**
- Data classification and handling within the SaaS application
- User identity and access management (user provisioning, MFA, SSO)
- Configuration of security settings (sharing permissions, access controls)
- Data loss prevention (DLP) policies
- Monitoring user activity and audit logs
- Compliance validation for data stored in SaaS
- Third-party integrations security

### 10.4 Shared Responsibility for XYZ's Architecture

For XYZ's hybrid Cloud + OnPremise architecture:

| Component | Responsibility | Notes |
|-----------|---------------|-------|
| Cloud K8S (CaaS - e.g., GKE/EKS/AKS) | **Shared**: CSP manages control plane; XYZ manages workloads, images, network policies, RBAC | CaaS model |
| Cloud App Web (PaaS or CaaS) | **XYZ**: Application code, WAF config, security headers | PaaS or CaaS model |
| Cloud BD Transaccional (PaaS - managed DB) | **Shared**: CSP manages DB engine patching; XYZ manages data encryption, access controls, backups | PaaS model |
| OnPremise (all components) | **100% XYZ**: Full stack responsibility | Not cloud |
| Cloud-OnPrem interconnection | **Shared**: CSP provides VPN/Interconnect service; XYZ configures, manages keys, monitors | Shared |

### 10.5 Common Pitfalls

| Pitfall | Description | Mitigation |
|---------|-------------|------------|
| **Assumption of full provider security** | Believing the CSP secures everything, leaving critical customer responsibilities unaddressed | Document and assign every layer of the shared responsibility model |
| **Identity gaps** | Not implementing proper IAM in the cloud, relying on default configurations | Enforce MFA, least privilege, and regular access reviews |
| **Data encryption neglect** | Assuming the provider encrypts data by default (not always true or sufficient) | Explicitly enable encryption at rest and in transit; manage your own keys when required |
| **Monitoring blind spots** | Not monitoring workloads because "the cloud handles it" | Implement application-level and workload-level monitoring alongside provider monitoring |
| **Compliance confusion** | Assuming provider certifications cover customer workloads | Customer must validate compliance for their own data and configurations |

---

## Task 11: Security in Container Architectures

### 11.1 Overview

Container security encompasses the **practices, tools, and policies** needed to protect containerized applications throughout their lifecycle — from image creation, through build and deployment, to runtime operation. Given that containers share the host OS kernel and can be ephemeral, traditional security approaches are insufficient; a container-native security strategy is required.

### 11.2 Security Measures by Lifecycle Phase

#### 11.2.1 Image Security

| Measure | Description | Tools |
|---------|-------------|-------|
| **Use minimal base images** | Use distroless (Google), Alpine, or scratch images. Fewer packages = smaller attack surface. Avoid full OS images (ubuntu, centos) unless necessary. | Google Distroless, Alpine Linux |
| **Vulnerability scanning** | Scan images for known CVEs in OS packages and application dependencies. Integrate into CI/CD as a gate. | **Trivy**, **Grype**, Anchore, Snyk Container |
| **No secrets in images** | Never bake API keys, passwords, certificates, or connection strings into container images. Use runtime injection. | GitLeaks (for Dockerfiles), Hadolint |
| **Non-root user** | Run containers as a non-root user. Define `USER` directive in Dockerfile. Prevents privilege escalation if container is compromised. | Hadolint (linting rule) |
| **Image signing** | Cryptographically sign images to verify integrity and provenance. Only deploy signed images. | **Cosign** (Sigstore), Notary v2 |
| **Trusted registries only** | Pull images only from approved private registries. Block access to public registries in production. | Harbor, ECR, GCR, ACR |
| **Regular image rebuilds** | Rebuild and rescan images regularly (weekly minimum) to incorporate latest security patches in base images. | CI/CD scheduled pipelines |

**Dockerfile Best Practices:**
```dockerfile
# Use specific version tag, never "latest"
FROM node:20-alpine AS builder

# Create non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy and install dependencies (leverage layer caching)
COPY package*.json ./
RUN npm ci --only=production

# Copy application code
COPY --chown=appuser:appgroup . .

# Switch to non-root user
USER appuser

# Use HEALTHCHECK
HEALTHCHECK --interval=30s CMD wget -q -O /dev/null http://localhost:3000/health

# Don't expose unnecessary ports
EXPOSE 3000
```

#### 11.2.2 Build Security

| Measure | Description | Tools |
|---------|-------------|-------|
| **Multi-stage builds** | Separate build and runtime stages. Build tools, source code, and intermediate artifacts are NOT present in the final image. Reduces attack surface and image size. | Docker multi-stage builds |
| **CI/CD security gates** | Fail the pipeline if critical/high vulnerabilities are found. No deployment without passing security checks. | Jenkins, GitHub Actions, GitLab CI with security scanning stages |
| **Dockerfile linting** | Lint Dockerfiles for security misconfigurations (running as root, using latest tag, exposing unnecessary ports). | **Hadolint**, Dockle |
| **Private registry** | Push images only to a private, authenticated container registry. Enable image immutability (prevent tag overwrites). | Harbor, ECR, GCR, ACR |
| **SBOM generation** | Generate Software Bill of Materials for every image. Enables tracking of all components and their vulnerabilities. | **Syft**, Trivy SBOM, Docker Scout |
| **Reproducible builds** | Ensure builds are deterministic and reproducible. Pin all dependency versions. | `npm ci`, `pip freeze`, lock files |

#### 11.2.3 Runtime Security

| Measure | Description | Tools |
|---------|-------------|-------|
| **Read-only filesystem** | Mount the container filesystem as read-only (`readOnlyRootFilesystem: true`). Only allow writes to specific tmpfs volumes. Prevents attackers from modifying binaries or writing malicious files. | Kubernetes Pod Security Context |
| **Drop all capabilities** | Remove all Linux capabilities and only add back those strictly needed (`drop: ALL`, then `add: NET_BIND_SERVICE` if required). | Kubernetes securityContext |
| **Seccomp profiles** | Apply seccomp (secure computing mode) profiles to restrict system calls available to the container. Use `RuntimeDefault` at minimum. | Kubernetes securityContext, custom seccomp profiles |
| **AppArmor / SELinux** | Mandatory Access Control profiles that restrict container processes. Limit file access, network operations, and capabilities. | AppArmor profiles, SELinux policies |
| **Resource limits** | Set CPU and memory limits and requests on all containers. Prevents resource exhaustion attacks (cryptomining, fork bombs). | Kubernetes resource limits |
| **No privilege escalation** | Set `allowPrivilegeEscalation: false` to prevent processes from gaining more privileges than their parent. | Kubernetes Pod Security Context |
| **Runtime threat detection** | Monitor container behavior at runtime. Alert on anomalies: unexpected process execution, shell spawning, file modifications, network connections to unusual destinations. | **Falco**, Sysdig Secure, Aqua Runtime |

**Example Kubernetes Security Context:**
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
```

#### 11.2.4 Orchestration Security (Kubernetes-Specific)

| Measure | Description | Tools |
|---------|-------------|-------|
| **Network Policies** | Define which pods can communicate with each other. Default deny all ingress/egress, then allow only necessary traffic. | Kubernetes Network Policies, Calico, Cilium |
| **RBAC** | Role-Based Access Control for Kubernetes API. Principle of least privilege for users and service accounts. Never use cluster-admin for workloads. | Kubernetes RBAC |
| **Pod Security Standards** | Enforce pod security at namespace level: Privileged, Baseline, or Restricted. Use Restricted for production workloads. | Kubernetes Pod Security Admission |
| **Admission Controllers** | Validate and mutate incoming workload definitions. Enforce organizational policies at deploy time. | **OPA/Gatekeeper**, **Kyverno** |
| **Namespace isolation** | Separate workloads by environment/team/sensitivity in different namespaces. Apply resource quotas and network policies per namespace. | Kubernetes Namespaces |
| **Etcd encryption** | Encrypt Kubernetes secrets at rest in etcd. Use KMS provider for key management. | Kubernetes encryption at rest configuration |
| **API server hardening** | Disable anonymous auth, enable audit logging, restrict API access to authorized networks. | CIS Kubernetes Benchmark Section 1 |

#### 11.2.5 Network Security

| Measure | Description | Tools |
|---------|-------------|-------|
| **Service Mesh with mTLS** | Automatic mutual TLS between all services. Zero-trust networking within the cluster. Also provides observability, circuit breaking, and traffic management. | **Istio**, **Linkerd**, Consul Connect |
| **Namespace segmentation** | Separate sensitive workloads (e.g., payment services) into dedicated namespaces with strict network policies. | Kubernetes Network Policies |
| **Ingress Controller with WAF** | Secure ingress point for external traffic. Apply WAF rules, rate limiting, and TLS termination. | NGINX Ingress + ModSecurity, AWS ALB Ingress |
| **Egress control** | Restrict outbound traffic from containers. Only allow connections to known, approved external services. Prevents data exfiltration. | Network Policies, Istio Egress Gateway |
| **DNS policies** | Control DNS resolution within the cluster to prevent DNS-based data exfiltration. | CoreDNS policies, Network Policies |

#### 11.2.6 Secrets Management

| Measure | Description | Tools |
|---------|-------------|-------|
| **External secret management** | Store and manage secrets in a dedicated, encrypted secrets management system. Inject at runtime. | **HashiCorp Vault**, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager |
| **External Secrets Operator** | Kubernetes operator that syncs secrets from external vaults into K8s secrets, keeping them up to date. | External Secrets Operator, Vault Agent Injector |
| **Sealed Secrets** | Encrypt K8s secrets so they can be safely stored in Git repositories (GitOps-friendly). Only the cluster can decrypt them. | **Sealed Secrets** (Bitnami) |
| **Never in images or env vars** | Secrets must never be baked into container images or stored in plain-text environment variables (visible via `docker inspect`). | Code reviews, secret scanning |
| **Secret rotation** | Implement automatic secret rotation with zero-downtime. Vault and cloud secret managers support this natively. | Vault dynamic secrets, AWS Secrets Manager rotation |

#### 11.2.7 Monitoring and Observability

| Measure | Description | Tools |
|---------|-------------|-------|
| **Centralized logging** | Aggregate logs from all containers into a centralized logging system. Include security-relevant events. | ELK Stack, Loki + Grafana, Splunk |
| **Runtime threat detection** | Detect suspicious activities in real-time: unauthorized process spawning, unexpected network connections, file modifications. | **Falco**, Sysdig Secure |
| **Anomaly detection** | ML-based detection of abnormal container behavior (CPU/memory spikes, unusual API calls, lateral movement). | Sysdig, Prisma Cloud |
| **Audit logging** | Enable Kubernetes audit logging for all API server requests. Detect unauthorized access attempts and privilege escalation. | Kubernetes Audit Logs |
| **Security dashboards** | Visualize security posture: vulnerability trends, policy violations, runtime alerts. | Grafana, Kibana, Sysdig dashboards |

### 11.3 Container Security Summary Table

| Phase | Key Principle | Critical Actions |
|-------|--------------|-----------------|
| **Build** | Secure by default | Minimal images, no secrets, non-root, scanning, signing |
| **Deploy** | Policy enforcement | Admission controllers, Pod Security Standards, RBAC |
| **Runtime** | Least privilege | Read-only FS, drop capabilities, seccomp, resource limits |
| **Network** | Zero trust | mTLS, network policies, egress control, ingress WAF |
| **Secrets** | External management | Vault, no env vars, rotation, sealed secrets |
| **Monitor** | Continuous visibility | Falco, centralized logs, audit trails, anomaly detection |

---

## Task 12: Kubernetes vs Containers

### 12.1 What Are Containers?

**Containers** are lightweight, portable units of software that package an **application together with all its dependencies** (libraries, runtime, system tools, configuration files) into a single, self-contained unit. Containers run on the host operating system, sharing its kernel, but are **isolated** from each other and from the host through Linux kernel features.

#### Core Technologies and Components

| Component | Description |
|-----------|-------------|
| **Container Image** | An immutable, layered file system that contains the application, its dependencies, and metadata. Built from a Dockerfile or similar specification. Stored in container registries. |
| **Container Runtime** | The software responsible for running containers. Manages the lifecycle: create, start, stop, delete. |
| **Linux Namespaces** | Kernel feature that provides isolation: PID namespace (process isolation), NET namespace (network isolation), MNT namespace (filesystem isolation), UTS namespace (hostname), IPC namespace (inter-process communication), USER namespace (user ID mapping). |
| **Control Groups (cgroups)** | Kernel feature that limits and accounts for resource usage (CPU, memory, disk I/O, network) per container. Prevents one container from consuming all host resources. |
| **Union/Overlay Filesystem** | Layered filesystem that enables efficient image storage. Multiple read-only layers are stacked, with a writable layer on top for runtime changes. |
| **OCI Standards** | Open Container Initiative defines standards for container images (Image Spec) and runtimes (Runtime Spec), ensuring interoperability. |

#### Container Runtime Implementations

| Runtime | Description | Use Case |
|---------|-------------|----------|
| **Docker** | Most widely known container platform. Includes Docker Engine (daemon), Docker CLI, Docker Compose. Uses containerd under the hood. | Development, CI/CD, standalone container management |
| **containerd** | Industry-standard container runtime. Graduated CNCF project. Used by Docker and Kubernetes. | Production Kubernetes clusters |
| **CRI-O** | Lightweight container runtime specifically built for Kubernetes. Implements Kubernetes Container Runtime Interface (CRI). | Kubernetes-focused environments (OpenShift uses CRI-O) |
| **Podman** | Daemonless container engine. Docker-compatible CLI. Rootless containers by default. | Security-focused environments, development without Docker daemon |
| **runc** | Low-level OCI runtime. The actual component that creates and runs containers using Linux kernel features. Used by containerd and CRI-O. | Underlying runtime (not used directly by users) |

#### How Containers Work (Simplified)

```
┌─────────────────────────────────────────────────────┐
│                    HOST OS (Linux)                   │
│                                                     │
│  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
│  │Container A│  │Container B│  │Container C│       │
│  │┌─────────┐│  │┌─────────┐│  │┌─────────┐│       │
│  ││  App A  ││  ││  App B  ││  ││  App C  ││       │
│  │├─────────┤│  │├─────────┤│  │├─────────┤│       │
│  ││  Libs A ││  ││  Libs B ││  ││  Libs C ││       │
│  │└─────────┘│  │└─────────┘│  │└─────────┘│       │
│  └───────────┘  └───────────┘  └───────────┘       │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │           Container Runtime                  │    │
│  │         (containerd / CRI-O)                │    │
│  └─────────────────────────────────────────────┘    │
│                                                     │
│  ┌─────────────────────────────────────────────┐    │
│  │      Linux Kernel (shared)                  │    │
│  │   Namespaces | cgroups | Overlay FS         │    │
│  └─────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────┘
```

### 12.2 What is Kubernetes?

**Kubernetes** (K8s) is an open-source **container orchestration platform** originally developed by Google (based on their internal system Borg). It automates the **deployment, scaling, networking, and management** of containerized applications at scale.

Kubernetes does NOT run containers directly — it orchestrates container runtimes (containerd, CRI-O) to manage the lifecycle of containers across a cluster of machines.

#### Kubernetes Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     KUBERNETES CLUSTER                        │
│                                                              │
│  ┌──────────────────────── Control Plane ──────────────────┐ │
│  │                                                          │ │
│  │  ┌──────────────┐  ┌──────┐  ┌──────────────────────┐  │ │
│  │  │kube-apiserver│  │ etcd │  │   kube-scheduler     │  │ │
│  │  │(API gateway) │  │(store)│  │(pod placement)       │  │ │
│  │  └──────────────┘  └──────┘  └──────────────────────┘  │ │
│  │                                                          │ │
│  │  ┌──────────────────────┐  ┌────────────────────────┐   │ │
│  │  │kube-controller-mgr   │  │cloud-controller-mgr    │   │ │
│  │  │(reconciliation loops)│  │(cloud provider APIs)    │   │ │
│  │  └──────────────────────┘  └────────────────────────┘   │ │
│  └──────────────────────────────────────────────────────────┘ │
│                              │                                │
│                              │ API calls                      │
│                              ▼                                │
│  ┌────────────────────── Worker Nodes ─────────────────────┐ │
│  │                                                          │ │
│  │  ┌─── Node 1 ──────────┐  ┌─── Node 2 ──────────┐     │ │
│  │  │ ┌────────┐           │  │ ┌────────┐           │     │ │
│  │  │ │kubelet │ (agent)   │  │ │kubelet │ (agent)   │     │ │
│  │  │ └────────┘           │  │ └────────┘           │     │ │
│  │  │ ┌──────────┐         │  │ ┌──────────┐         │     │ │
│  │  │ │kube-proxy│(network)│  │ │kube-proxy│(network)│     │ │
│  │  │ └──────────┘         │  │ └──────────┘         │     │ │
│  │  │ ┌──────────────────┐ │  │ ┌──────────────────┐ │     │ │
│  │  │ │Container Runtime │ │  │ │Container Runtime │ │     │ │
│  │  │ │(containerd)      │ │  │ │(containerd)      │ │     │ │
│  │  │ └──────────────────┘ │  │ └──────────────────┘ │     │ │
│  │  │ ┌──────┐ ┌──────┐   │  │ ┌──────┐ ┌──────┐   │     │ │
│  │  │ │Pod A │ │Pod B │   │  │ │Pod C │ │Pod D │   │     │ │
│  │  │ └──────┘ └──────┘   │  │ └──────┘ └──────┘   │     │ │
│  │  └──────────────────────┘  └──────────────────────┘     │ │
│  └──────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────┘
```

#### Control Plane Components

| Component | Function |
|-----------|----------|
| **kube-apiserver** | The front-end API for the Kubernetes cluster. All internal and external communication goes through the API server. It validates and processes REST requests, updates state in etcd. |
| **etcd** | Distributed, consistent key-value store that holds ALL cluster state and configuration data. The single source of truth. Must be backed up regularly and encrypted at rest. |
| **kube-scheduler** | Watches for newly created Pods with no assigned node. Selects the optimal node based on resource requirements, constraints, affinity/anti-affinity rules, and policies. |
| **kube-controller-manager** | Runs controller loops that monitor cluster state and make changes to move toward the desired state. Includes: Node Controller, Replication Controller, Endpoints Controller, Service Account Controller. |
| **cloud-controller-manager** | Integrates with cloud provider APIs. Manages cloud-specific resources: load balancers, persistent volumes, node lifecycle in the cloud. |

#### Worker Node Components

| Component | Function |
|-----------|----------|
| **kubelet** | Agent running on every worker node. Ensures that containers described in PodSpecs are running and healthy. Reports node and pod status to the API server. |
| **kube-proxy** | Network proxy running on every node. Maintains network rules that allow network communication to Pods. Implements Kubernetes Service abstraction (ClusterIP, NodePort, LoadBalancer). |
| **Container Runtime** | The software responsible for running containers (containerd, CRI-O). Kubelet communicates with the runtime via the Container Runtime Interface (CRI). |

#### Key Kubernetes Objects

| Object | Description |
|--------|-------------|
| **Pod** | Smallest deployable unit. Contains one or more containers that share network namespace (same IP) and storage volumes. Ephemeral by design. |
| **Deployment** | Declares the desired state for Pods (replicas, image version, update strategy). Manages ReplicaSets for rolling updates and rollbacks. |
| **Service** | Stable network endpoint for accessing a set of Pods. Types: ClusterIP (internal), NodePort (external via node port), LoadBalancer (cloud LB). |
| **Ingress** | Manages external HTTP/HTTPS access to Services. Provides URL routing, SSL termination, name-based virtual hosting. |
| **ConfigMap** | Stores non-sensitive configuration data as key-value pairs. Decouples configuration from container images. |
| **Secret** | Stores sensitive data (passwords, tokens, keys). Base64 encoded by default (NOT encrypted unless etcd encryption is enabled). |
| **Namespace** | Virtual cluster within a physical cluster. Provides scope for names, resource quotas, and network policies. Used for environment/team isolation. |
| **PersistentVolume (PV) / PersistentVolumeClaim (PVC)** | Storage abstraction. PV represents a piece of storage; PVC is a request for storage by a user/Pod. |
| **NetworkPolicy** | Defines rules for network traffic between Pods. Used for micro-segmentation and zero-trust networking within the cluster. |
| **ServiceAccount** | Identity for processes running in Pods. Used for RBAC to control API access for workloads. |

### 12.3 Relationship Between Kubernetes and Containers

```
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                    KUBERNETES                                │
│            (Orchestration Platform)                          │
│                                                             │
│   Provides: Scheduling, Scaling, Networking,                │
│   Self-healing, Service Discovery, Load Balancing,          │
│   Rolling Updates, Secret Management, RBAC                  │
│                                                             │
│         ┌──────────────────────────────────┐                │
│         │                                  │                │
│         │         CONTAINERS               │                │
│         │      (Execution Units)           │                │
│         │                                  │                │
│         │   Provides: Application          │                │
│         │   isolation, portability,        │                │
│         │   reproducible environments      │                │
│         │                                  │                │
│         └──────────────────────────────────┘                │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**The relationship is hierarchical and complementary:**

| Aspect | Containers | Kubernetes |
|--------|-----------|------------|
| **Role** | The **unit of execution** — packages and runs an individual application | The **orchestrator** — manages containers across a cluster at scale |
| **Scope** | Single application + its dependencies | Entire distributed system of containerized applications |
| **Analogy** | A shipping container (standardized box) | The shipping port (logistics, routing, scheduling, tracking) |
| **Without the other** | Containers can run standalone (Docker, Podman) but managing many is complex | Kubernetes cannot function without a container runtime |
| **Scaling** | No native multi-host scaling | Auto-scales Pods (HPA), Nodes (cluster autoscaler) |
| **Networking** | Basic port mapping | Service discovery, load balancing, ingress routing, network policies |
| **Self-healing** | If a container crashes, it stays crashed | Automatically restarts failed containers, reschedules on healthy nodes |
| **Updates** | Manual stop/start with new image | Rolling updates with zero downtime, automatic rollback on failure |
| **State management** | Stateless by default | Manages persistent storage, config, and secrets for stateful workloads |

### 12.4 Key Differentiators Summary

| Feature | Containers (Docker/Podman) | Kubernetes (K8s) |
|---------|--------------------------|-------------------|
| **What it is** | Runtime for packaging and executing applications | Platform for orchestrating containers at scale |
| **Abstraction level** | Process-level isolation | Cluster-level management |
| **Scaling** | Manual | Automatic (HPA, VPA, Cluster Autoscaler) |
| **Load Balancing** | External tools needed | Built-in (Services, Ingress) |
| **Self-healing** | None (restart policies only) | Full (rescheduling, health checks, liveness/readiness probes) |
| **Service Discovery** | DNS-based (Docker Compose) | Built-in (CoreDNS, Services) |
| **Secret Management** | Environment variables, files | Secrets API (with optional encryption) |
| **Networking** | Bridge networks, host networking | CNI plugins, Network Policies, Service Mesh |
| **Storage** | Volumes, bind mounts | PersistentVolumes, StorageClasses, CSI drivers |
| **Use Case** | Single-host development, small deployments | Production multi-host distributed systems |

### 12.5 When to Use What

| Scenario | Recommendation |
|----------|---------------|
| Local development and testing | **Containers** (Docker, Docker Compose, Podman) |
| Small application, 1-3 services, single host | **Containers** with Docker Compose |
| Production with 5+ microservices requiring scaling | **Kubernetes** |
| High availability and zero-downtime deployments required | **Kubernetes** |
| Need automatic scaling based on load | **Kubernetes** (HPA + Cluster Autoscaler) |
| Multi-cloud or hybrid cloud deployments | **Kubernetes** (portable across cloud providers) |
| XYZ's financial portal microservices (K8S layer) | **Kubernetes** — already using K8S for microservices; ideal for financial workloads requiring HA, scaling, and security controls |

---

# APPENDIX

## References

### Standards and Frameworks
- ISO/IEC 27001:2022 - Information Security Management Systems
- ISO/IEC 27005:2022 - Information Security Risk Management
- NIST SP 800-30 Rev. 1 - Guide for Conducting Risk Assessments
- NIST Cybersecurity Framework (CSF) 2.0
- NIST SP 800-53 Rev. 5 - Security and Privacy Controls
- OWASP Top 10:2021
- OWASP API Security Top 10:2023
- OWASP Application Security Verification Standard (ASVS) v4.0
- PCI-DSS v4.0
- CIS Kubernetes Benchmark v1.8
- MITRE ATT&CK Framework

### Colombian Regulations
- Ley 1581 de 2012 - Proteccion de Datos Personales
- Decreto 1377 de 2013 - Reglamentacion de Ley 1581
- Circular Externa 007 de 2018 (SFC) - Ciberseguridad
- Circular Externa 042 de 2012 (SFC) - Seguridad en Canales Electronicos

---

*Document generated on February 18, 2026*
*Regional Security Expert Assessment - XYZ Financial Services*
