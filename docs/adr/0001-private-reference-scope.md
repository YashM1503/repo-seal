# ADR 0001: Keep RepoLab as a private reference incubator

- Status: Accepted
- Date: 2026-08-09

## Context

The original proposal combined repository-history mining, replayable coding-agent tasks, configuration comparison, statistical promotion, benchmark auditing, and automatic configuration optimization. Current tools and research collectively cover that loop, with Stet presenting the closest end-to-end collision.

At the same time, the red-team memo identified reusable engineering primitives that could improve interoperability and experimental validity.

## Decision

Create a private repository limited to schemas, task-quality gates, verifier-boundary contracts, and reproducible decision receipts.

No external release or product positioning is authorized by this decision. Any public release requires a new review of novelty, security, licensing, and evidence of ecosystem pull.

## Consequences

- The repository can accumulate learning without prematurely creating a public category claim.
- Early work remains deterministic and safe to run locally because it executes no untrusted code.
- Sandbox, agent, GitHub, and provider integrations are deferred.
- The absence of a dashboard is intentional.
- Milestones can be terminated cheaply if interoperability or validation value does not appear.
