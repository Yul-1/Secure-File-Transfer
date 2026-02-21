# Changelog

All notable changes to the Docker configuration will be documented in this file.

## [2026-02-22]

### Changed

- **docker-compose.yml**: Added custom bridge network `sft-net` with subnet `192.168.0.0/24`, gateway `192.168.0.1`. Server assigned static IP `192.168.0.201`.
- **docker-compose.yml**: Added timezone synchronization with host via `TZ=Europe/Rome` environment variable and `/etc/localtime` bind mount. Fixes SFT protocol timestamp validation failure caused by UTC/CET offset between container and host.
- **docker-compose.yml**: Replaced TCP socket healthcheck with process-based check (`pgrep -f sft.py`). The previous healthcheck opened and immediately closed TCP connections to port 5555, causing spurious handshake failure warnings in server logs.

## [2026-02-21]

### Added

- **Docker directory**: Created dedicated `Docker/` directory at project root level, alongside `C/`, `RUST/`, and `Windows/` subdirectories, to centralize all container-related configuration.

- **Dockerfile.rust**: Multi-stage Dockerfile for the Rust implementation.
  - Stage 1 (builder): Based on `python:3.12-slim`. Installs build toolchain (`build-essential`, `python3-dev`, `pkg-config`), Rust compiler via `rustup`, Python dependencies from `requirements.txt`, and compiles the `crypto_accelerator` PyO3 module using `maturin build --release`. The resulting wheel is installed into the builder's site-packages.
  - Stage 2 (runtime): Based on `python:3.12-slim`. Copies only `sft.py`, `python_wrapper.py`, and the pre-built site-packages from the builder stage. Runs as non-root user `sftuser` (UID 1000). Exposes port 5555 and defines `/app/ricevuti` as a volume for received files. No Rust toolchain or build dependencies are present in the final image.

- **docker-compose.yml**: Compose configuration for the SFT server.
  - Service `sft-server` with build context pointing to `../RUST` and dockerfile reference to `../Docker/Dockerfile.rust`.
  - Port mapping `5555:5555` (TCP).
  - Named volume `sft-data` mounted at `/app/ricevuti` for persistent file storage.
  - Restart policy `unless-stopped`.
  - `PYTHONUNBUFFERED=1` environment variable for real-time log output.
  - Health check: TCP socket connection test to port 5555 every 30 seconds.

- **RUST/.dockerignore**: Excludes `venv/`, `target/`, `__pycache__/`, `.pytest_cache/`, `tests/`, `ricevuti/`, log files, and IDE/editor directories from the Docker build context to reduce image size and prevent leaking unnecessary files.
