# Bundle Module (Air-Gapped Offline Packaging & Diagnostics)

The `bundle` module manages self-contained, air-gapped distribution archives, Docker container image imports/exports, integrity manifests, and operational environment readiness diagnostics (`readyhai doctor`).

## Architecture

- **`env.rs`**: Offline environment guard state (`offline()`) and shared test mutex (`ENV_LOCK`).
- **`eol.rs`**: End-of-life runtime catalog parsing and upstream synchronization.
- **`manifest.rs`**: Bundle manifest format (`Manifest`, `FileEntry`, `ImageEntry`), recursive file discovery, and SHA256 integrity verification.
- **`tar.rs`**: System archive security enforcement (path traversal prevention) and filesystem operations.
- **`export.rs`**: Packaging offline bundles on connected machines (`export`).
- **`import.rs`**: Unpacking and loading verified container images and vulnerability databases on air-gapped systems (`import`).
- **`doctor.rs`**: Host diagnostic suite checking disk space, Docker connectivity, tool caching, and LLM reachability (`doctor`).
- **`tests.rs`**: Deterministic unit tests covering manifest tamper detection, tar path traversal rejections, and offline guards.
