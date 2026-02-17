# Dockerfile INTENCIONALMENTE inseguro para demostracion
# Ver task-11 para la version hardened
FROM python:3.11
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5000
# VULNERABILIDAD: Ejecuta como root, debug habilitado
CMD ["python", "app.py"]
