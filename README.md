# Virus Scanner

Report-only Tauri antivirus scanner MVP built with React, shadcn/ui, and Rust.

## What It Does

- Scans files and folders on demand.
- Hashes each file with SHA-256 and BLAKE3.
- Runs YARA-X rules against file bytes.
- Parses executable metadata with `object`.
- Traverses folders with `walkdir` and scans ZIP, TAR, and GZIP contents within configured depth and size limits.
- Performs optional hash-only VirusTotal lookups with `GET /api/v3/files/{sha256}`.
- Classifies file content with Magika when the local ONNX runtime is available.
- Reports findings only. It does not upload, quarantine, delete, block, install drivers, or register AMSI providers.

## Environment

`VIRUSTOTAL_API_KEY`
: Enables VirusTotal hash lookups. If unset, local scans still run and cloud status is disabled.

`VIRUSSCANNER_YARA_RULES`
: Optional path list of `.yar` / `.yara` files or directories.

`VIRUSSCANNER_HASH_DB`
: Optional JSON hash indicator database.

## Development

```powershell
rtk bun install
rtk bun run build
rtk cargo test --manifest-path src-tauri/Cargo.toml
rtk cargo check --manifest-path src-tauri/Cargo.toml
```

The Rust API contract is exported to `src/bindings` with `ts-rs` during `cargo test`, and the React app imports those generated types.
