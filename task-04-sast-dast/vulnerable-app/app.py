#!/usr/bin/env python3
"""
ADVERTENCIA: Aplicacion INTENCIONALMENTE VULNERABLE para demostracion.
NO usar en produccion. Contiene vulnerabilidades de OWASP Top 10
para demostrar la deteccion por herramientas SAST y DAST.

Portal Financiero XYZ - App de Demo para Pruebas de Seguridad
"""

from flask import Flask, request, render_template_string, jsonify, redirect
import sqlite3
import hashlib
import os
import pickle
import base64

app = Flask(__name__)

# VULNERABILIDAD: Secret key hardcodeada (CWE-798, Risk R-11)
app.secret_key = "super_secret_key_12345_xyz_financial"

# VULNERABILIDAD: Credenciales de BD hardcodeadas (CWE-798)
DB_HOST = "db.xyz-financial.internal"
DB_USER = "admin"
DB_PASS = "P@ssw0rd_Pr0d!"  # nosec - intencionalmente vulnerable
DB_NAME = "financial_portal"
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"

# VULNERABILIDAD: API Key hardcodeada
STRIPE_API_KEY = "sk_test_EJEMPLO_NO_REAL_000000000"  # nosec - fake key


def get_db():
    """Conexion a base de datos en memoria para demo."""
    db = sqlite3.connect(":memory:")
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            balance REAL
        )
    """)
    db.execute(
        "INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@xyz.com', 50000.00)"
    )
    db.commit()
    return db


@app.route("/")
def index():
    return render_template_string("""
    <h1>Portal Financiero XYZ - Demo Vulnerable</h1>
    <p>Esta aplicacion contiene vulnerabilidades intencionales para pruebas SAST/DAST.</p>
    <ul>
        <li><a href="/login">Login (SQL Injection)</a></li>
        <li><a href="/profile?name=test">Profile (XSS)</a></li>
        <li><a href="/search?q=test">Search (XSS)</a></li>
        <li><a href="/download?file=test.txt">Download (Path Traversal)</a></li>
        <li><a href="/hash?pw=test">Hash (Weak Algorithm)</a></li>
    </ul>
    """)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string("""
        <h2>Login</h2>
        <form method="POST">
            <input name="username" placeholder="Username"><br>
            <input name="password" type="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
        """)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # VULNERABILIDAD: SQL Injection (CWE-89, Risk R-02)
    # Concatenacion directa de input del usuario en query SQL
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

    db = get_db()
    try:
        result = db.execute(query).fetchone()
        if result:
            return jsonify({"status": "success", "user": result[1], "balance": result[4]})
        return jsonify({"status": "error", "message": "Credenciales invalidas"}), 401
    except Exception as e:
        # VULNERABILIDAD: Information Disclosure (CWE-209)
        # Stack trace expuesto al usuario
        return jsonify({"error": str(e)}), 500


@app.route("/profile")
def profile():
    name = request.args.get("name", "")
    # VULNERABILIDAD: XSS Reflejado (CWE-79, Risk R-03)
    # Input del usuario renderizado sin sanitizacion
    return render_template_string(f"<h1>Bienvenido {name}</h1><p>Portal Financiero XYZ</p>")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    # VULNERABILIDAD: XSS Reflejado (CWE-79)
    html = f"""
    <h2>Resultados de busqueda para: {query}</h2>
    <p>No se encontraron resultados.</p>
    """
    return render_template_string(html)


@app.route("/transfer", methods=["POST"])
def transfer():
    # VULNERABILIDAD: Sin proteccion CSRF (CWE-352, Risk R-06)
    # VULNERABILIDAD: Sin validacion server-side de montos (CWE-472, Risk R-07)
    amount = request.form.get("amount", 0)
    destination = request.form.get("destination", "")

    # No hay validacion de que el monto sea positivo o dentro de limites
    return jsonify({
        "status": "success",
        "amount": amount,
        "destination": destination,
        "message": "Transferencia realizada"
    })


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # VULNERABILIDAD: Path Traversal (CWE-22, Risk R-22)
    # Sin sanitizacion del nombre de archivo
    filepath = os.path.join("/uploads", filename)
    try:
        with open(filepath, "r") as f:
            return f.read()
    except FileNotFoundError:
        return "Archivo no encontrado", 404
    except Exception as e:
        return str(e), 500


@app.route("/hash")
def hash_password():
    password = request.args.get("pw", "")
    # VULNERABILIDAD: Hash debil MD5 (CWE-328)
    # MD5 es criptograficamente roto, usar bcrypt o argon2
    hashed = hashlib.md5(password.encode()).hexdigest()
    return jsonify({"algorithm": "MD5", "hash": hashed})


@app.route("/deserialize", methods=["POST"])
def deserialize():
    data = request.form.get("data", "")
    # VULNERABILIDAD: Deserializacion insegura (CWE-502)
    try:
        obj = pickle.loads(base64.b64decode(data))
        return jsonify({"result": str(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/health")
def health():
    return jsonify({"status": "healthy"})


if __name__ == "__main__":
    # VULNERABILIDAD: Debug mode habilitado (CWE-489)
    # Expone stack traces y permite ejecucion de codigo
    app.run(debug=True, host="0.0.0.0", port=5000)
