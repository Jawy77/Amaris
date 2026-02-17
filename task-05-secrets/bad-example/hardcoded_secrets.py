"""
ADVERTENCIA: ARCHIVO DE DEMOSTRACION - SECRETOS FALSOS
Este archivo contiene credenciales FALSAS para demostrar lo que las
herramientas de escaneo de secrets detectan. NUNCA hacer esto en codigo real.

CWE-798: Use of Hard-coded Credentials
CWE-259: Use of Hard-coded Password
OWASP A07:2021: Security Misconfiguration
"""

# BAD: Connection string con credenciales (CWE-798)
DATABASE_URL = "postgresql://admin:SuperSecret123!@db.xyz-financial.com:5432/production"

# BAD: API keys hardcodeadas
STRIPE_SECRET_KEY = "sk_test_EJEMPLO_NO_REAL_000000000"
PLAID_CLIENT_SECRET = "FAKE_plaid_secret_0123456789abcdef"

# BAD: Credenciales AWS
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# BAD: JWT secret en codigo
JWT_SECRET = "my-super-secret-jwt-signing-key-that-should-be-rotated"

# BAD: Contrasena SMTP
SMTP_PASSWORD = "email_password_123"

# BAD: Token de base de datos
MONGO_URI = "mongodb://dbuser:dbpass123@cluster0.example.mongodb.net/financial"

# BAD: Google Cloud credentials
GCP_SERVICE_ACCOUNT_KEY = '{"type":"service_account","project_id":"xyz-prod","private_key":"FAKE_KEY"}'

# BAD: Contrasena en funcion
def connect_to_database():
    """Ejemplo de lo que NO se debe hacer."""
    import psycopg2
    conn = psycopg2.connect(
        host="db.xyz-financial.com",
        database="production",
        user="admin",
        password="P@ssw0rd_Pr0d!_2026"  # NUNCA hacer esto
    )
    return conn
