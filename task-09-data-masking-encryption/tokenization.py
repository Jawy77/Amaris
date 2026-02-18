#!/usr/bin/env python3
"""
Tokenizacion - Portal Financiero XYZ (PCI-DSS)
Referencia: Task 9 Seccion 9.4

Simula un vault de tokenizacion para datos de tarjeta de credito.
En produccion: usar servicios como Stripe, Braintree o HashiCorp Vault Transit.
"""

import uuid
import hashlib
import json
from datetime import datetime


class TokenVault:
    """
    Vault de tokenizacion para datos de tarjeta de credito.
    Almacena mapeo token -> PAN cifrado.
    En produccion: base de datos cifrada en PCI CDE aislado.
    """

    def __init__(self):
        self._vault = {}
        self._audit_log = []

    def tokenize(self, pan, metadata=None):
        """
        Reemplazar PAN con un token aleatorio.
        El PAN original se almacena en el vault (cifrado en produccion).
        """
        # Validar formato basico
        digits = pan.replace("-", "").replace(" ", "")
        if not digits.isdigit() or len(digits) < 13:
            raise ValueError("PAN invalido")

        # Generar token unico
        token = f"tok_{uuid.uuid4().hex[:16]}"

        # Almacenar en vault
        self._vault[token] = {
            "pan": digits,
            "pan_hash": hashlib.sha256(digits.encode()).hexdigest(),
            "created_at": datetime.utcnow().isoformat(),
            "metadata": metadata or {},
            "access_count": 0,
        }

        # Audit log
        self._log("TOKENIZE", token, f"PAN ***{digits[-4:]}")

        return token

    def detokenize(self, token, requester="system"):
        """
        Recuperar PAN original desde token.
        Solo servicios autorizados pueden llamar esta funcion.
        """
        entry = self._vault.get(token)
        if not entry:
            self._log("DETOKENIZE_FAILED", token, f"Token no encontrado - requester: {requester}")
            raise ValueError(f"Token no encontrado: {token}")

        entry["access_count"] += 1
        self._log("DETOKENIZE", token, f"Acceso por: {requester} (acceso #{entry['access_count']})")

        return entry["pan"]

    def get_last_four(self, token):
        """Obtener ultimos 4 digitos sin detokenizar completamente."""
        entry = self._vault.get(token)
        if not entry:
            raise ValueError(f"Token no encontrado: {token}")
        return f"****-****-****-{entry['pan'][-4:]}"

    def get_masked(self, token):
        """Obtener PAN enmascarado (primeros 6, ultimos 4)."""
        entry = self._vault.get(token)
        if not entry:
            raise ValueError(f"Token no encontrado: {token}")
        pan = entry["pan"]
        return f"{pan[:6]}{'*' * (len(pan) - 10)}{pan[-4:]}"

    def revoke_token(self, token):
        """Revocar/eliminar un token del vault."""
        if token in self._vault:
            self._log("REVOKE", token, "Token revocado permanentemente")
            del self._vault[token]
            return True
        return False

    def get_audit_log(self):
        """Obtener registro de auditoria."""
        return self._audit_log.copy()

    def _log(self, action, token, detail):
        """Registrar operacion en audit log."""
        self._audit_log.append({
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "token": token,
            "detail": detail,
        })


# =============================================================================
# Demo
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  TOKENIZACION PCI-DSS - Portal Financiero XYZ")
    print("=" * 70)

    vault = TokenVault()

    # --- Tokenizar tarjetas ---
    print("\n--- Tokenizacion ---\n")
    cards = [
        ("4532-7891-2345-6789", {"titular": "Juan Perez", "tipo": "Visa"}),
        ("5425-2334-3010-9903", {"titular": "Maria Lopez", "tipo": "Mastercard"}),
        ("3714-496353-98431", {"titular": "Carlos Rodriguez", "tipo": "Amex"}),
    ]

    tokens = []
    for pan, meta in cards:
        token = vault.tokenize(pan, meta)
        tokens.append(token)
        print(f"  PAN: {pan}")
        print(f"  Token: {token}")
        print(f"  Enmascarado: {vault.get_masked(token)}")
        print(f"  Ultimos 4: {vault.get_last_four(token)}")
        print()

    # --- Detokenizar ---
    print("--- Detokenizacion (solo servicios autorizados) ---\n")
    for token in tokens:
        pan = vault.detokenize(token, requester="payment-service")
        print(f"  Token: {token} -> PAN: {pan}")
    print()

    # --- Revocar ---
    print("--- Revocacion de Token ---\n")
    print(f"  Revocando token: {tokens[0]}")
    vault.revoke_token(tokens[0])
    try:
        vault.detokenize(tokens[0])
    except ValueError as e:
        print(f"  Resultado: {e} (correcto - token revocado)")
    print()

    # --- Audit Log ---
    print("--- Audit Log (PCI-DSS 10.1) ---\n")
    for entry in vault.get_audit_log():
        print(f"  [{entry['timestamp']}] {entry['action']}: {entry['detail']}")
