# Changelog

All notable changes to the Docker configuration will be documented in this file.

## [2026-02-22]

### Changed

- **docker-compose.yml**: Added custom bridge network `sft-net` with subnet `192.168.0.0/24`, gateway `192.168.0.1`. Server assigned static IP `192.168.0.201`.
- **docker-compose.yml**: Added timezone synchronization with host via `TZ=Europe/Rome` environment variable and `/etc/localtime` bind mount. Fixes SFT protocol timestamp validation failure caused by UTC/CET offset between container and host.
- **docker-compose.yml**: Replaced TCP socket healthcheck with process-based check (`pgrep -f sft.py`). The previous healthcheck opened and immediately closed TCP connections to port 5555, causing spurious handshake failure warnings in server logs.

### Next Steps

Based on the Docker Evaluation and Security Audit reports, the following improvements are planned in priority order.

#### Phase 1: Critical Fixes

- [ ] Replace `curl | sh` Rustup installation with official `rust:1.75-slim` builder image to eliminate supply chain attack vector
- [ ] Add resource limits (`cpus`, `memory`, `pids`) to docker-compose to prevent DoS via resource exhaustion
- [ ] Replace `pgrep` healthcheck with functional TCP socket check that suppresses protocol handshake (or add a dedicated health endpoint to `sft.py`)
- [ ] Configure log rotation (`json-file` driver with `max-size` and `max-file`) to prevent unbounded disk growth

#### Phase 2: Security Hardening

- [ ] Drop all Linux capabilities (`cap_drop: ALL`) since port 5555 does not require `NET_BIND_SERVICE`
- [ ] Add `security_opt: no-new-privileges:true` to prevent privilege escalation
- [ ] Set `read_only: true` on root filesystem with `tmpfs` mounts for `/tmp` and writable paths
- [ ] Change `sftuser` UID from 1000 to a high UID (e.g. 65534) to avoid host UID collision
- [ ] Restrict `/app/*.py` to read-only (chmod 500) so only `/app/ricevuti` is writable
- [ ] Pin base image by digest (`python:3.12-slim@sha256:...`) and APT package versions for reproducible builds
- [ ] Evaluate upgrading `cryptography` library from 43.0.1 to address known CVEs

#### Phase 3: Build Optimization

- [ ] Implement Cargo dependency caching layer (dummy `lib.rs` build before copying source) for 2-5x faster rebuilds
- [ ] Split `requirements.txt` into `requirements-runtime.txt` and `requirements-build.txt` to exclude test deps (pytest, freezegun) from final image (~30MB reduction)
- [ ] Add `ARG` directives for Python/Rust version pinning
- [ ] Evaluate Alpine base image for ~50% image size reduction (currently 239MB)
- [ ] Add `STOPSIGNAL SIGTERM` for graceful shutdown

#### Phase 4: Production Readiness

- [ ] Implement secrets management via Docker secrets for any future authentication keys
- [ ] Add TLS termination (reverse proxy or application-level)
- [ ] Configure centralized logging (syslog or ELK/Loki)
- [ ] Add Prometheus metrics exporter for monitoring
- [ ] Set up automated volume backup with retention policy
- [ ] Evaluate multi-replica deployment with load balancer for high availability
- [ ] Add multi-platform build support (linux/amd64, linux/arm64)

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
