# Licensing and provenance audit

## Scope and authoritative license

This repository's top-level `LICENSE` file is the authoritative project license and it is the Apache License, Version 2.0. The project metadata has been aligned to match that intent.

This audit is limited to licensing metadata and provenance documentation. It does not change application behavior.

## Project metadata status

The published Python package metadata in `pyproject.toml` now states:

- `license = "Apache-2.0"`

The legacy `License :: OSI Approved :: Apache Software License` classifier was removed because modern setuptools treats license classifiers as deprecated when a PEP 639 license expression is present; keeping the license expression and removing the separate classifier preserves valid package metadata while still identifying the project as Apache-2.0.

The first-party Rust crate in `crates/core/Cargo.toml` now states:

- `license = "Apache-2.0"`

This keeps the Python and Rust packaging metadata consistent with the Apache-2.0 project license.

## Third-party dependency inventory

### Python dependencies declared by the project

These are the direct Python dependencies currently declared in `pyproject.toml` and verified from the installed package metadata in the environment:

| Package | Version | License | Notes |
| --- | --- | --- | --- |
| click | 8.1.6 | BSD-3-Clause | CLI framework |
| jinja2 | 3.1.2 | BSD-3-Clause | Template engine |
| pydantic | 1.10.14 | MIT | Data validation |
| requests | 2.31.0 | Apache 2.0 | HTTP client |
| packaging | 24.0 | Apache Software License / BSD-like metadata | Version parsing |
| PyYAML | 6.0.1 | MIT | YAML parsing |
| tomli | 2.0.1 | MIT | Python 3.10 compatibility |

The `requests` dependency is Apache-2.0, consistent with the project's chosen license. This project does not distribute or vendor those libraries in source form; they are runtime dependencies consumed by Python packaging.

### Rust dependencies

The Rust extension in `crates/core/Cargo.toml` pulls in a normal crates.io dependency set (`pyo3`, `serde`, `serde_json`, `half`). The generated `Cargo.lock` confirms the transitive dependency graph, including `pyo3`, `serde`, `half`, and supporting crates from crates.io. Those are third-party dependencies of the Rust extension, not content copied into this repository.

The repository does not currently contain a vendored third-party notice for those crates. A project-level NOTICE is therefore limited to the project's own copyright and a pointer to the dependency records; it is not a blanket claim that every transitive dependency is incorporated into NOTICE text.

### chardet audit

`chardet` is not a declared dependency of this project. The direct dependency list in `pyproject.toml` does not include it, and `requests` only declares `chardet` as an optional extra (`requests[use_chardet_on_py3]`), not as a mandatory requirement.

Evidence from the current environment:

- `importlib.metadata.requires('requests')` shows `chardet<6,>=3.0.2; extra == "use_chardet_on_py3"`
- `importlib.metadata.distribution('chardet')` reports `License: LGPL`

This means `chardet` can appear in a specific environment because a user or toolchain installed `requests` with the optional `use_chardet_on_py3` extra, or because another package in the environment brought it in. It is not an inherent runtime dependency of AI-BOM Inspector itself. The project therefore does not claim to be LGPL or to ship LGPL code solely because `chardet` happens to be present in one installation environment.

## NOTICE file guidance

Apache 2.0 does not require every Apache-2.0 project to include a NOTICE file. A NOTICE is relevant when the project distributes a work that includes third-party notices or when the distribution contains materials that require preservation or attribution.

This repository keeps a minimal NOTICE file at the project root reflecting:

- the project copyright
- the Apache 2.0 license
- a reference to dependency and provenance documentation instead of broad, unverified attribution claims

This avoids the legal overreach of claiming that every dependency belongs in a project-level NOTICE when only the actual, documented dependency set and generated SBOM records are the relevant sources of truth.

## Training source fingerprint audit

File audited: `src/aibom_inspector/data/training_source_fingerprints.json`

### Findings

1. The file contains a small rule set with entries such as `common crawl`, `web crawl`, and `reddit`, paired with risk labels and notes.
2. These entries are not copied training corpora or redistributable datasets; they are heuristic pattern identifiers used by the project's risk scanner to classify likely data sources.
3. The file does not contain personal data or raw crawled text payloads; it is a compact metadata catalog of risk patterns.
4. The file is not a direct third-party dataset redistribution in the copyright sense. It is project-generated metadata describing classes of training/source risk.
5. The file does carry a provenance risk: the names `common crawl` and `web crawl` can be read as references to third-party source categories rather than verified provenance claims, so they should be treated as operational heuristics rather than factual statements about any specific dataset source.

### Risk and recommendation

The highest-risk aspect is not the presence of copied content; it is the possibility that a future maintainer reads these strings as factual provenance metadata. They are not factual provenance records and should be handled as generalized heuristic labels.

Recommended remediation:

- keep the file as a project-generated risk pattern database, not as a redistributable source dataset
- avoid descriptive labels that imply a specific dataset or crawl was incorporated into this project
- document that entries are heuristic match patterns, not statements of third-party factual provenance
- consider replacing source-name labels like `common crawl` with intentionally generic labels (for example, `public-web-index-heuristic`, `forum-content-heuristic`) when upstream provenance is not independently verified

This is a compliant and conservative approach that preserves the scanner's functionality without implying that the project is redistributing copyrighted or sensitive source material.

## Human/legal review items

The following should be reviewed by a human legal or compliance reviewer before any public or commercial release:

- whether any third-party materials are bundled or redistributed outside the package metadata and generated SBOM
- whether a formal third-party attribution list is required for a particular distribution channel or compliance regime
- whether the training-source fingerprint rules require stricter provenance documentation for model-risk use cases
- whether a future version of the project adds curated source names that need explicit permission and attribution tracking

This project should not claim legal compliance beyond the documented review above.
