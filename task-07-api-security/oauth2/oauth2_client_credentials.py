#!/usr/bin/env python3
"""
OAuth2 Client Credentials Flow - Integracion API XYZ <-> Proveedor 123
Referencia: Task 7 Seccion 7.3.1

Implementa:
- Token Server (lado XYZ): emite tokens JWT con scopes
- Middleware de verificacion: valida tokens en cada request
- Cliente demo (lado Proveedor 123): solicita y usa tokens
"""

import time
import uuid
import hmac
import hashlib
import json
from functools import wraps
from flask import Flask, request, jsonify

app = Flask(__name__)

# En produccion: desde Vault/Secret Manager
JWT_SECRET = "demo-secret-key-replace-in-production"
TOKEN_EXPIRY = 900  # 15 minutos

# Registro de clientes autorizados
REGISTERED_CLIENTS = {
    "provider_123_client_id": {
        "secret_hash": hashlib.sha256(b"provider_123_secret").hexdigest(),
        "allowed_scopes": ["read:sales", "read:billing", "write:orders"],
        "rate_limit": 100,
        "description": "Proveedor 123 - Integracion de ventas y billing"
    }
}


def create_jwt(payload):
    """Crear JWT simple (demo). En produccion usar PyJWT con RS256."""
    header = {"alg": "HS256", "typ": "JWT"}

    def b64encode(data):
        import base64
        return base64.urlsafe_b64encode(
            json.dumps(data).encode()
        ).rstrip(b"=").decode()

    header_b64 = b64encode(header)
    payload_b64 = b64encode(payload)
    signature = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).hexdigest()

    return f"{header_b64}.{payload_b64}.{signature}"


def verify_jwt(token):
    """Verificar JWT. En produccion usar PyJWT."""
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token invalido")

    header_b64, payload_b64, signature = parts

    # Verificar firma
    expected_sig = hmac.new(
        JWT_SECRET.encode(),
        f"{header_b64}.{payload_b64}".encode(),
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(signature, expected_sig):
        raise ValueError("Firma invalida")

    # Decodificar payload
    padding = 4 - len(payload_b64) % 4
    payload_b64 += "=" * padding
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))

    # Verificar expiracion
    if payload.get("exp", 0) < time.time():
        raise ValueError("Token expirado")

    return payload


# =============================================================================
# Token Server (lado XYZ)
# =============================================================================

@app.route("/oauth/token", methods=["POST"])
def issue_token():
    """Endpoint para solicitar access token (Client Credentials Grant)."""
    grant_type = request.form.get("grant_type")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    requested_scopes = request.form.get("scope", "").split()

    # Validar grant type
    if grant_type != "client_credentials":
        return jsonify({"error": "unsupported_grant_type"}), 400

    # Validar cliente
    client = REGISTERED_CLIENTS.get(client_id)
    if not client:
        return jsonify({"error": "invalid_client"}), 401

    # Validar secret
    secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    if not hmac.compare_digest(secret_hash, client["secret_hash"]):
        return jsonify({"error": "invalid_client"}), 401

    # Filtrar scopes permitidos
    granted_scopes = [s for s in requested_scopes if s in client["allowed_scopes"]]
    if not granted_scopes:
        granted_scopes = client["allowed_scopes"]

    # Generar token
    now = int(time.time())
    token = create_jwt({
        "sub": client_id,
        "scope": " ".join(granted_scopes),
        "iat": now,
        "exp": now + TOKEN_EXPIRY,
        "jti": str(uuid.uuid4()),
        "iss": "xyz-financial-portal",
    })

    return jsonify({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRY,
        "scope": " ".join(granted_scopes),
    })


# =============================================================================
# Middleware de autorizacion
# =============================================================================

def require_scope(required_scope):
    """Decorador para proteger endpoints con scope OAuth2."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "missing_token"}), 401

            token = auth_header[7:]
            try:
                payload = verify_jwt(token)
                scopes = payload.get("scope", "").split()
                if required_scope not in scopes:
                    return jsonify({"error": "insufficient_scope"}), 403
                request.token_payload = payload
            except ValueError as e:
                return jsonify({"error": str(e)}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


# =============================================================================
# APIs protegidas
# =============================================================================

@app.route("/api/v1/sales")
@require_scope("read:sales")
def get_sales():
    """Endpoint de ventas - requiere scope read:sales."""
    return jsonify({
        "data": [
            {"id": 1, "product": "Cuenta Ahorros Premium", "amount": 1500.00},
            {"id": 2, "product": "Tarjeta Credito Gold", "amount": 3200.00},
        ],
        "client": request.token_payload["sub"]
    })


@app.route("/api/v1/billing")
@require_scope("read:billing")
def get_billing():
    """Endpoint de facturacion - requiere scope read:billing."""
    return jsonify({
        "data": [
            {"invoice": "INV-001", "amount": 850.00, "status": "paid"},
        ],
        "client": request.token_payload["sub"]
    })


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    print("=== OAuth2 Token Server - XYZ Financial Portal ===")
    print("Endpoints:")
    print("  POST /oauth/token   - Solicitar access token")
    print("  GET  /api/v1/sales  - Ventas (scope: read:sales)")
    print("  GET  /api/v1/billing - Billing (scope: read:billing)")
    print()
    app.run(host="0.0.0.0", port=8080)
