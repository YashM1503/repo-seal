# ADR 0005: Publish BenchSeal under Apache License 2.0

- Status: Accepted
- Date: 2026-08-16

## Context

ADR 0001 kept the original RepoLab concept private because its broad product scope overlapped existing systems and its agent-execution boundary was not safe. ADRs 0002 through 0004 extracted and completed a much narrower product: BenchSeal validates evidence recorded by a trusted process and does not execute arbitrary repositories or real coding agents.

The completed validator MVP is useful as a reviewable open-source primitive. Publishing it requires an explicit license and must not be interpreted as reviving the rejected RepoLab product or approving the research runners for hostile workloads.

## Decision

Publish BenchSeal under the Apache License, Version 2.0, beginning with version 1.0.1. Use the SPDX expression `Apache-2.0` in package metadata and include the canonical license text at the repository root.

Apache-2.0 is preferred over MIT for this project because it provides an explicit patent grant and defines the terms applied to intentionally submitted contributions. Those provisions are useful for developer infrastructure that may receive implementation contributions from multiple organizations.

Before changing repository visibility, verify the current tree and Git history do not contain credentials or private artifacts, run the complete release checks, and publish the licensed release commit.

## Scope that remains closed

Public availability does not change any security decision:

- the broad history-mining and agent-optimization product remains a no-go;
- real or untrusted agent execution remains unsupported;
- the Docker research backend is not an independently approved sandbox;
- `security_gate_passed` and `safe_for_real_agents` remain false; and
- an `ELIGIBLE` receipt still depends on the honesty and quality of supplied observations.

## Consequences

- Anyone may use, modify, and redistribute BenchSeal under Apache-2.0.
- Intentionally submitted contributions are licensed under Apache-2.0 unless explicitly stated otherwise.
- Packaging and documentation must identify the public repository and license accurately.
- Any future expansion beyond the evidence validator needs a separate product and security decision.
