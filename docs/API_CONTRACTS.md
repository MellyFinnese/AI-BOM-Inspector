# API Contracts

This document defines the formal API contract strategy for AI-BOM Inspector and links to the versioned OpenAPI and AsyncAPI specifications.

## Goals

- Provide a single source of truth for client/server integration.
- Enable contract testing and schema validation.
- Support backward-compatible evolution with explicit versioning.

## REST contract (OpenAPI)

- **Spec location**: `schemas/openapi/control-plane.v1.yaml`
- **Primary consumers**: Control Plane API clients, SDK generators, documentation.
- **Versioning**: SemVer at the contract level (v1.x). Breaking changes require a new `v2` file and `/v2/...` base path.

## Event contract (AsyncAPI)

- **Spec location**: `schemas/asyncapi/control-plane-events.v1.yaml`
- **Primary consumers**: Event-driven integrations, webhooks, internal messaging.
- **Versioning**: SemVer at the contract level (v1.x). Breaking changes require new channels or a new `v2` spec file.

## Schema versioning strategy

- **Schema files are versioned by filename** (e.g., `control-plane.v1.yaml`).
- **Payloads include explicit version fields** where applicable (e.g., `bundle_version`, `schema_version`).
- **Backward-compatible changes**: additive fields, optional fields, new enum values with safe defaults.
- **Breaking changes**: removing fields, changing required fields, or changing data types. These require a new versioned schema file.

## Contract validation (aspirational)

- OpenAPI validation gates for Control Plane client libraries.
- AsyncAPI validation for event payloads in CI.
- JSON schema validation for evidence bundles and policy artifacts during ingestion.
