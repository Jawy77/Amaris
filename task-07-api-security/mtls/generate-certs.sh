#!/bin/bash
# =============================================================================
# Generacion de Certificados mTLS - Demo
# Referencia: Task 7 - Seccion 7.3.1
# En produccion: usar PKI corporativa (Vault PKI, AWS ACM Private CA)
# =============================================================================

set -euo pipefail

CERT_DIR="$(dirname "$0")/certs"
mkdir -p "$CERT_DIR"

echo "============================================="
echo "  Generacion de Certificados mTLS"
echo "  Portal Financiero XYZ <-> Proveedor 123"
echo "============================================="

echo ""
echo "[1/3] Generando CA (Certificate Authority)..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" \
  -subj "/CN=XYZ Financial Portal CA/O=XYZ Corp/C=CO/ST=Bogota" \
  2>/dev/null

echo "[2/3] Generando certificado del servidor (XYZ)..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" \
  -subj "/CN=api.xyz-financial.com/O=XYZ Corp/C=CO" \
  2>/dev/null

openssl x509 -req \
  -in "$CERT_DIR/server.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/server.crt" \
  -days 365 \
  2>/dev/null

echo "[3/3] Generando certificado del cliente (Proveedor 123)..."
openssl req -newkey rsa:4096 -nodes \
  -keyout "$CERT_DIR/client.key" \
  -out "$CERT_DIR/client.csr" \
  -subj "/CN=api-client.provider123.com/O=Provider 123/C=CO" \
  2>/dev/null

openssl x509 -req \
  -in "$CERT_DIR/client.csr" \
  -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERT_DIR/client.crt" \
  -days 365 \
  2>/dev/null

# Limpiar CSRs
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.srl

echo ""
echo "============================================="
echo "  Certificados generados exitosamente"
echo "============================================="
echo "  CA:      $CERT_DIR/ca.crt"
echo "  Server:  $CERT_DIR/server.crt | $CERT_DIR/server.key"
echo "  Client:  $CERT_DIR/client.crt | $CERT_DIR/client.key"
echo ""
echo "  Verificar: openssl verify -CAfile $CERT_DIR/ca.crt $CERT_DIR/server.crt"
echo "============================================="
