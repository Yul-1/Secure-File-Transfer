# ============================================================
# Dockerfile per SFT - Alpine Linux Multi-Stage Build
# ============================================================

# Stage 1: Builder - Usa l'ultima versione stabile di Rust
FROM rust:alpine AS builder

# Aggiunto 'patchelf' alla lista dei pacchetti
RUN apk add --no-cache \
    python3 \
    python3-dev \
    py3-pip \
    musl-dev \
    gcc \
    g++ \
    libffi-dev \
    openssl-dev \
    patchelf

WORKDIR /build

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY src/ ./src/
COPY requirements.txt ./

# Crea venv, installa maturin e compila
RUN python3 -m venv /build/venv && \
    . /build/venv/bin/activate && \
    pip install --no-cache-dir maturin && \
    maturin build --release && \
    pip install --no-cache-dir cryptography jsonschema PySocks

# Stage 2: Runtime - Allineato a Python 3.12
FROM python:3.12-alpine

RUN apk add --no-cache libgcc libstdc++ ca-certificates && \
    addgroup -g 1000 sftuser && \
    adduser -D -u 1000 -G sftuser sftuser

WORKDIR /app

# Copia modulo Rust compilato
COPY --from=builder /build/target/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Copia dipendenze Python (path allineati a python3.12)
COPY --from=builder /build/venv/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Copia applicazione
COPY sft.py python_wrapper.py ./

RUN mkdir -p /app/ricevuti /app/logs && \
    chown -R sftuser:sftuser /app

USER sftuser

EXPOSE 5555

ENV PYTHONUNBUFFERED=1

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('127.0.0.1', 5555)); s.close()" || exit 1

CMD ["python3", "sft.py", "--mode", "server", "--host", "0.0.0.0", "--port", "5555"]