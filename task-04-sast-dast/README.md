# Task 4: Pruebas SAST y DAST

## Descripcion
Implementacion practica de escaneo de seguridad estatico (SAST) y dinamico (DAST) para el portal financiero XYZ.

## Componentes

### App Vulnerable (Demo)
`vulnerable-app/` contiene una aplicacion Flask intencionalmente vulnerable para demostrar los hallazgos de los scanners:
- SQL Injection (CWE-89)
- XSS Reflejado (CWE-79)
- Credenciales hardcodeadas (CWE-798)
- Path Traversal (CWE-22)
- Hash debil MD5 (CWE-328)
- Debug mode en produccion (CWE-489)

### SAST con Semgrep
```bash
# Ejecutar Semgrep con reglas custom
semgrep --config sast/.semgrep.yml vulnerable-app/
```

### DAST con OWASP ZAP
```bash
# Levantar app vulnerable
cd vulnerable-app && docker build -t vuln-app . && docker run -p 5000:5000 vuln-app

# Ejecutar ZAP (en otro terminal)
docker run -t zaproxy/zap-stable zap-baseline.py -t http://host.docker.internal:5000
```

## Referencia
Documento completo: Secciones 4.1 a 4.5
