# Task 1: Analisis de Riesgos

## Descripcion
Registro de riesgos en formato YAML machine-readable y generador de heatmap visual basado en la metodologia ISO 27005:2022 + NIST SP 800-30.

## Uso

```bash
pip install -r requirements.txt
python risk_matrix.py
```

Esto genera:
- Heatmap visual en `risk_heatmap.png`
- Tabla de riesgos ordenados por severidad en stdout

## Archivos
- `risk_register.yaml` - Registro estructurado de los 23 riesgos identificados
- `risk_matrix.py` - Script que genera el mapa de calor
- `requirements.txt` - Dependencias Python

## Referencia
Documento completo: [docs/Regional_Security_Expert_Response.md](../docs/Regional_Security_Expert_Response.md) - Secciones 1.1 a 1.5
