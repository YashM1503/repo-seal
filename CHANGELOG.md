# Changelog

This file records user-visible BenchSeal changes. Dates use `YYYY-MM-DD`.

## 1.0.1 — 2026-08-16

- Released the narrow BenchSeal validator as public open-source software under the Apache License 2.0.
- Added SPDX packaging metadata, public repository links, and explicit contribution licensing.
- Preserved the no-go decision for the broader RepoLab product and all closed real-agent security gates.

## 1.0.0 — 2026-08-16

BenchSeal 1.0 closes the narrow task-evidence validation MVP.

### Added

- A fail-closed `new-evidence` command whose unmeasured observations start as `null`.
- Validation of one evidence file or a nonrecursive directory of evidence files.
- Deterministic task-set receipts, duplicate task-ID detection, and aggregate decisions.
- A documented MVP acceptance boundary and release checklist.

### Fixed

- CI now invokes the installed `benchseal` package instead of the removed `repolab_reference` module.
- The Docker integration job now sets the opt-in variable the test actually checks.
- An out-of-range CI Docker Engine is reported as unavailable evidence instead of weakening the pinned security policy or failing the validator MVP gate.
- The host negative control explicitly allows the macOS-managed child-process text-encoding key while continuing to reject arbitrary inherited environment keys.
- Receipt output uses exclusive creation and cannot replace an existing file or symbolic link.

### Security boundary

- Evidence collection, arbitrary repository execution, and real-agent adapters remain out of scope.
- `security_gate_passed` and `safe_for_real_agents` remain `false` pending an independently authenticated review of the exact commit and scope digest.

## 0.9.0 — 2026-08-16

- Added the evidence draft and task-set validation workflow used to complete 1.0.

## 0.8.0 — 2026-08-16

- Renamed the narrow validator to BenchSeal and introduced the installable validation MVP surface.
