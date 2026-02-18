#!/usr/bin/env python3
"""
Data Masking - Portal Financiero XYZ
Referencia: Task 9 Secciones 9.3 y 9.5

Demuestra:
- Static Data Masking (SDM)
- Dynamic Data Masking (DDM) basado en roles
- Generacion de datos falsos realistas
"""

import re
from faker import Faker

fake = Faker('es_CO')


# =============================================================================
# Static Data Masking (SDM)
# =============================================================================

def mask_credit_card(pan):
    """Enmascarar tarjeta de credito: mostrar primeros 6 y ultimos 4 (PCI-DSS)."""
    digits = re.sub(r'\D', '', str(pan))
    if len(digits) < 10:
        return "****"
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def mask_email(email):
    """Enmascarar email preservando primer y ultimo caracter."""
    if '@' not in email:
        return "***@***.***"
    local, domain = email.split('@')
    if len(local) <= 2:
        masked = local[0] + '*'
    else:
        masked = local[0] + '*' * (len(local) - 2) + local[-1]
    return f"{masked}@{domain}"


def mask_phone(phone):
    """Enmascarar telefono mostrando ultimos 4 digitos."""
    digits = re.sub(r'\D', '', str(phone))
    return f"***-***-{digits[-4:]}" if len(digits) >= 4 else "***"


def mask_cedula(cedula):
    """Enmascarar documento de identidad."""
    s = str(cedula)
    return f"{'*' * (len(s) - 4)}{s[-4:]}" if len(s) >= 4 else "****"


def generate_fake_customer():
    """Generar un cliente falso pero realista (Static Data Masking)."""
    return {
        "nombre": fake.name(),
        "email": fake.email(),
        "telefono": fake.phone_number(),
        "cedula": str(fake.random_number(digits=10, fix_len=True)),
        "direccion": fake.address().replace('\n', ', '),
        "ciudad": fake.city(),
    }


# =============================================================================
# Dynamic Data Masking (DDM) basado en roles
# =============================================================================

class DynamicMasker:
    """Enmascara datos en tiempo real segun el rol del usuario."""

    # Campos a enmascarar por rol
    ROLE_MASKS = {
        "admin": [],                                          # Ve todo
        "supervisor": ["cedula"],                             # Casi todo
        "soporte": ["credit_card", "cedula", "email"],        # Parcial
        "analista": ["credit_card", "cedula", "email", "phone", "nombre"],  # Minimo
    }

    MASK_FUNCTIONS = {
        "credit_card": mask_credit_card,
        "email": mask_email,
        "phone": mask_phone,
        "cedula": mask_cedula,
        "nombre": lambda n: n.split()[0][0] + "*** " + n.split()[-1][0] + "***" if ' ' in n else "***",
    }

    def mask_record(self, record, role):
        """Aplicar masking a un registro segun el rol."""
        fields_to_mask = self.ROLE_MASKS.get(role, list(self.MASK_FUNCTIONS.keys()))
        masked = record.copy()
        for field in fields_to_mask:
            if field in masked and field in self.MASK_FUNCTIONS:
                masked[field] = self.MASK_FUNCTIONS[field](masked[field])
        return masked


# =============================================================================
# Demo
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("  DATA MASKING - Portal Financiero XYZ")
    print("=" * 70)

    # --- Static Masking ---
    print("\n--- Static Data Masking (SDM) ---\n")
    examples = [
        ("Tarjeta de credito", "4532-7891-2345-6789", mask_credit_card),
        ("Email", "juan.perez@gmail.com", mask_email),
        ("Telefono", "+57 310 555 1234", mask_phone),
        ("Cedula", "1234567890", mask_cedula),
    ]
    for name, original, func in examples:
        print(f"  {name}:")
        print(f"    Original:    {original}")
        print(f"    Enmascarado: {func(original)}")
        print()

    # --- Fake Data Generation ---
    print("--- Generacion de Datos Falsos (SDM con Faker) ---\n")
    for i in range(3):
        customer = generate_fake_customer()
        print(f"  Cliente {i + 1}:")
        for key, value in customer.items():
            print(f"    {key}: {value}")
        print()

    # --- Dynamic Masking ---
    print("--- Dynamic Data Masking (DDM) por Rol ---\n")
    record = {
        "nombre": "Juan Carlos Perez",
        "credit_card": "4532789123456789",
        "email": "juan.perez@xyz.com",
        "cedula": "1234567890",
        "phone": "+57 310 555 1234",
    }
    print(f"  Registro original: {record}\n")

    masker = DynamicMasker()
    for role in ["admin", "supervisor", "soporte", "analista"]:
        masked = masker.mask_record(record, role)
        print(f"  Rol '{role}':")
        for k, v in masked.items():
            print(f"    {k}: {v}")
        print()
