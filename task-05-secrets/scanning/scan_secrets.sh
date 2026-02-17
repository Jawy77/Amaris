#!/bin/bash
# =============================================================================
# Script de Escaneo de Secrets - Portal Financiero XYZ
# Ejecuta multiples herramientas de deteccion de secrets
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "============================================="
echo "  Escaneo de Secrets - XYZ Financial Portal"
echo "============================================="
echo ""

FINDINGS=0

# --- Gitleaks ---
if command -v gitleaks &> /dev/null; then
    echo "[*] Ejecutando Gitleaks..."
    if gitleaks detect --source="$PROJECT_ROOT" \
        --config="$PROJECT_ROOT/.gitleaks.toml" \
        --report-format=json \
        --report-path="$SCRIPT_DIR/gitleaks-report.json" \
        --verbose 2>&1; then
        echo "[+] Gitleaks: Sin hallazgos"
    else
        GITLEAKS_COUNT=$(jq length "$SCRIPT_DIR/gitleaks-report.json" 2>/dev/null || echo "?")
        echo "[-] Gitleaks: $GITLEAKS_COUNT hallazgos detectados"
        FINDINGS=$((FINDINGS + 1))
    fi
else
    echo "[!] Gitleaks no instalado. Instalar: https://github.com/gitleaks/gitleaks"
fi

echo ""

# --- TruffleHog ---
if command -v trufflehog &> /dev/null; then
    echo "[*] Ejecutando TruffleHog..."
    trufflehog filesystem "$PROJECT_ROOT" \
        --json > "$SCRIPT_DIR/trufflehog-report.json" 2>/dev/null || true
    TRUFFLEHOG_COUNT=$(wc -l < "$SCRIPT_DIR/trufflehog-report.json" 2>/dev/null || echo "0")
    if [ "$TRUFFLEHOG_COUNT" -gt 0 ]; then
        echo "[-] TruffleHog: $TRUFFLEHOG_COUNT hallazgos detectados"
        FINDINGS=$((FINDINGS + 1))
    else
        echo "[+] TruffleHog: Sin hallazgos"
    fi
else
    echo "[!] TruffleHog no instalado. Instalar: https://github.com/trufflesecurity/trufflehog"
fi

echo ""
echo "============================================="
if [ "$FINDINGS" -gt 0 ]; then
    echo "  RESULTADO: SECRETS DETECTADOS"
    echo "  Revisar reportes en $SCRIPT_DIR/"
    exit 1
fi
echo "  RESULTADO: Sin secrets detectados"
echo "============================================="
