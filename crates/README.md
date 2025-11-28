# Rust crates

The `crates/` directory hosts the optional Rust accelerators and modular building blocks for AI-BOM Inspector. The current layout mirrors the major domains of the scanner so each concern can evolve independently:

- `core/` – shared parsing, normalization, and scoring logic (currently houses the `tensor_fuzz` PyO3 extension).
- `licenses/` – space reserved for SPDX/license rule helpers.
- `advisories/` – adapters for CVE and advisory ingestion (OSV/NVD/etc.).
- `report/` – renderers and diff helpers for report formats.

Each crate can be built on its own via Cargo, or bundled into the Python package through `setuptools-rust` when the optional acceleration is enabled.
