# Task 2: Controles de Seguridad

## Descripcion
Configuraciones de seguridad listas para produccion para el portal financiero XYZ. Incluye hardening de Nginx, WAF con ModSecurity y rate limiting.

## Archivos

### Nginx Security Headers
- `nginx/nginx-security-headers.conf` - Headers de seguridad (HSTS, CSP, X-Frame-Options, etc.)

### WAF (Web Application Firewall)
- `nginx/modsecurity.conf` - Configuracion de ModSecurity con OWASP CRS

### Rate Limiting
- `rate-limiting/rate_limit.conf` - Rate limiting por endpoint (auth, transacciones, uploads)

## Uso
Incluir las configuraciones en el bloque `server` de Nginx:

```nginx
include /etc/nginx/conf.d/security-headers.conf;
include /etc/nginx/conf.d/rate-limit.conf;
```

## Referencia
Documento completo: Secciones 2.2.1 a 2.2.8
