#!/usr/bin/env python3
"""
Data Encryption - Portal Financiero XYZ
Referencia: Task 9 Secciones 9.4 y 9.5

Demuestra:
- AES-256-CBC cifrado simetrico
- Cifrado en reposo para datos sensibles
- Hashing seguro para contrasenas (bcrypt/argon2 pattern)
"""

import os
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# =============================================================================
# AES-256-CBC Encryption
# =============================================================================

def aes256_encrypt(plaintext, key):
    """
    Cifrar datos con AES-256-CBC.
    Retorna (ciphertext, iv) en bytes.
    """
    iv = os.urandom(16)

    # Padding PKCS7
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode('utf-8')) + padder.finalize()

    # Cifrar
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext, iv


def aes256_decrypt(ciphertext, key, iv):
    """
    Descifrar datos con AES-256-CBC.
    Retorna plaintext como string.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Quitar padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext.decode('utf-8')


def encrypt_with_metadata(plaintext, key):
    """
    Cifrar con metadata embebida (IV + ciphertext) para almacenamiento.
    Retorna string base64 listo para guardar en BD.
    """
    ciphertext, iv = aes256_encrypt(plaintext, key)
    # Combinar IV + ciphertext y codificar en base64
    combined = iv + ciphertext
    return base64.b64encode(combined).decode('utf-8')


def decrypt_from_metadata(encoded_data, key):
    """
    Descifrar datos con metadata embebida.
    """
    combined = base64.b64decode(encoded_data)
    iv = combined[:16]
    ciphertext = combined[16:]
    return aes256_decrypt(ciphertext, key, iv)


# =============================================================================
# Hashing Seguro (para contrasenas)
# =============================================================================

def hash_password_secure(password, salt=None):
    """
    Hash seguro de contrasena usando PBKDF2-SHA256.
    En produccion: usar bcrypt o argon2.
    """
    if salt is None:
        salt = os.urandom(32)

    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations=600000  # OWASP recomendado: 600,000 para PBKDF2-SHA256
    )
    return salt + key  # salt (32 bytes) + hash (32 bytes)


def verify_password(password, stored_hash):
    """Verificar contrasena contra hash almacenado."""
    salt = stored_hash[:32]
    expected = hash_password_secure(password, salt)
    return hmac.compare_digest(stored_hash, expected)


# =============================================================================
# Demo
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  DATA ENCRYPTION - Portal Financiero XYZ")
    print("=" * 70)

    # Generar llave de 256 bits
    key = os.urandom(32)
    print(f"\n  Llave AES-256: {key.hex()[:32]}... ({len(key) * 8} bits)")

    # --- Cifrado AES-256 ---
    print("\n--- AES-256-CBC Encryption ---\n")

    test_data = [
        ("Tarjeta de credito", "4532-7891-2345-6789"),
        ("Email", "juan.perez@xyz-financial.com"),
        ("Monto transaccion", "$15,000.00 USD"),
        ("Cedula", "1234567890"),
    ]

    for label, plaintext in test_data:
        encrypted = encrypt_with_metadata(plaintext, key)
        decrypted = decrypt_from_metadata(encrypted, key)

        print(f"  {label}:")
        print(f"    Plaintext:  {plaintext}")
        print(f"    Cifrado:    {encrypted[:50]}...")
        print(f"    Descifrado: {decrypted}")
        print(f"    Integridad: {'OK' if decrypted == plaintext else 'FALLO'}")
        print()

    # --- Hashing Seguro ---
    print("--- Hashing Seguro de Contrasenas (PBKDF2-SHA256) ---\n")

    password = "MiContraseñaSegura!2026"
    stored = hash_password_secure(password)
    print(f"  Contrasena:     {password}")
    print(f"  Hash (hex):     {stored.hex()[:64]}...")
    print(f"  Longitud:       {len(stored)} bytes (32 salt + 32 hash)")
    print(f"  Verificacion:   {'CORRECTO' if verify_password(password, stored) else 'FALLO'}")
    print(f"  Contrasena mal: {'CORRECTO' if verify_password('incorrecta', stored) else 'RECHAZADA'}")
    print()

    # --- Comparacion MD5 vs PBKDF2 ---
    print("--- Comparacion: MD5 (inseguro) vs PBKDF2 (seguro) ---\n")
    print(f"  MD5 (NO USAR):   {hashlib.md5(password.encode()).hexdigest()}")
    print(f"  SHA1 (NO USAR):  {hashlib.sha1(password.encode()).hexdigest()}")
    print(f"  PBKDF2-SHA256:   {stored.hex()[:64]}...")
    print(f"  Iteraciones:     600,000 (OWASP recomendado)")
