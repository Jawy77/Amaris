# Task 7: Seguridad en Integracion API con Proveedor 123

## Descripcion
Implementacion de seguridad para la integracion API entre XYZ y el Proveedor 123.

## Componentes

### API Gateway con mTLS
`api-gateway/` - Configuracion Nginx como API Gateway con mutual TLS.

### OAuth2 Client Credentials
`oauth2/` - Implementacion del flujo machine-to-machine con tokens JWT.

### Certificados mTLS
```bash
cd mtls/
chmod +x generate-certs.sh
./generate-certs.sh
```

## Referencia
Documento completo: Secciones 7.1 a 7.6
