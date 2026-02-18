# =============================================================================
# Dockerfile Hardened - Portal Financiero XYZ
# Referencia: Task 8 (DevSecOps) + Task 11 (Container Security)
# Mejores practicas: multi-stage, non-root, minimal, health check
# =============================================================================

# Stage 1: Build (no se incluye en imagen final)
FROM python:3.11-alpine AS builder

WORKDIR /build

# Instalar dependencias de compilacion (solo en build stage)
RUN apk add --no-cache gcc musl-dev libffi-dev

# Copiar e instalar dependencias
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Produccion (imagen minima)
FROM python:3.11-alpine AS production

# Metadata
LABEL maintainer="security@xyz-financial.com"
LABEL description="Portal Financiero XYZ - Imagen Hardened"
LABEL version="1.0.0"

# Crear usuario non-root (Seccion 11.2.1)
RUN addgroup -S appgroup && \
    adduser -S appuser -G appgroup -h /app -s /sbin/nologin

# Actualizar paquetes base y eliminar cache
RUN apk update && \
    apk upgrade --no-cache && \
    rm -rf /var/cache/apk/*

# Copiar dependencias desde builder
COPY --from=builder /install /usr/local

# Directorio de trabajo
WORKDIR /app

# Copiar codigo de aplicacion
COPY --chown=appuser:appgroup . .

# Cambiar a usuario non-root
USER appuser:appgroup

# Health check (Seccion 11.2.1)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO /dev/null http://localhost:8000/health || exit 1

# Solo exponer el puerto necesario
EXPOSE 8000

# Usar exec form (no shell form) para senales correctas
ENTRYPOINT ["gunicorn"]
CMD ["--bind", "0.0.0.0:8000", "--workers", "4", "--timeout", "120", \
     "--access-logfile", "-", "--error-logfile", "-", "app:create_app()"]
