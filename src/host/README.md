# Host Target Inspection & Auditing Module (`src/host`)

## Responsibility
Audits remote Linux, macOS, and Windows hosts over OpenSSH by piping OS probe scripts, synthesizing CycloneDX SBOMs for Grype CVE matching, and executing Lynis system hardening audits.

## Files
- `mod.rs`: Facade re-exports for checks, probe parsing, SSH runners, and Lynis auditing.
- `types.rs`: Core structures (`ProbeResult`, `SshOut`, `LynisReport`) and embedded probe script constants.
- `redact.rs`: Log sanitization masking passwords, API tokens, AWS keys, bearer headers, and hex blobs.
- `ssh.rs`: OpenSSH parameter building (`ssh_args`), child process piping (`run_ssh`), and remote execution.
- `probe/mod.rs`: OS probe analysis dispatcher.
- `probe/common.rs`: JSON probe field extraction and cross-platform checks (SSHD configuration, disk saturation).
- `probe/linux.rs`: Linux-specific systemd, firewall, sudoers, time-sync, and container restart checks.
- `probe/macos.rs`: macOS-specific SIP, Gatekeeper, FileVault, and application firewall checks.
- `probe/windows.rs`: Windows-specific Defender status, Firewall profiles, SMBv1, RDP NLA, and updates.
- `probe/sbom.rs`: CycloneDX 1.5 package inventory synthesis.
- `lynis.rs`: Lynis report parsing, hardening index assessment, and tarball downloader/verifier.
- `runner.rs`: Check orchestrators (`host.probe`, `host.cve`, `host.lynis`).
- `tests.rs`: Comprehensive test suite verifying golden outputs for Linux, macOS, and Windows.

## Public Interfaces
- `checks() -> Vec<Check>`
- `fetch_lynis(cache_dir: &Path) -> Result<()>`
- `parse_probe(os: Os, v: &Value, who: &str) -> ProbeResult`
- `sbom_from_probe(v: &Value) -> Option<Value>`
- `parse_lynis(report: &str) -> LynisReport`
- `lynis_findings(r: &LynisReport, who: &str) -> Vec<Finding>`
- `run_ssh(h: &HostSpec, remote_cmd: &str, stdin: Vec<u8>, timeout: Duration) -> Result<SshOut>`
- `ssh_args(h: &HostSpec, remote_cmd: &str) -> Result<Vec<String>>`
- `redact_line(line: &str) -> String`

## Tests
```bash
cargo test --bin readyhai -- host::tests
```
