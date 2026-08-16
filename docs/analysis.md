# Analysis of the RepoLab red-team memo

> **2026-08-16 update:** The broad RepoLab product remains a no-go. The narrow task-evidence validator shipped as BenchSeal and was subsequently renamed RepoSeal for clarity. See [ADR 0002](adr/0002-benchseal-mvp.md) and [ADR 0006](adr/0006-reposeal-rename.md). This does not authorize the original mining, agent-comparison, or automatic-optimization product.

## Decision

The memo's strategic conclusion is sound: **do not build or market RepoLab as a new end-to-end product category**. Use this private repository only to test small, reusable primitives and to discover a genuinely unserved seam.

## What was verified

The two most important premises were checked against current primary sources on 9 August 2026:

1. **Direct product collision is real.** Stet describes replaying real work from a repository, comparing model, harness, reasoning, instruction, skill, and configuration changes, and keeping changes that win. Its methodology starts from merged pull requests, resets the repository to the pre-merge state, runs agents, executes the original tests, and scores correctness, equivalence, review quality, footprint, and cost.
2. **Benchmark validity is a first-order problem.** OpenAI reported on 8 July 2026 that its audit estimated roughly 30% of SWE-Bench Pro tasks are broken, highlighting overly strict tests, underspecified prompts, low-coverage tests, and misleading prompts.
3. **Task-generation infrastructure is occupied.** SWE-smith already supports scalable software-engineering task and environment construction from repositories.

These facts are enough to reject the original novelty claim without needing every adjacent project in the memo to be equally mature.

## Strong parts of the memo

- It distinguishes an important problem from an attractive product opportunity.
- It treats the complete deployment unit—not just the model—as the experimental subject.
- It correctly rejects a merged human patch as a perfect oracle.
- It recognizes multiple-comparison and holdout-overfitting risks.
- It makes verifier isolation, future-history removal, network denial, and cache isolation architectural requirements.
- It proposes falsification gates before feature development.

## Claims that need calibration

- A competitive scan can establish collision, but it cannot prove that no commercial wedge exists. The right conclusion is “insufficient evidence to build,” not metaphysical certainty that the category has no whitespace.
- Competitor self-descriptions are evidence of overlap, not independent proof that their implementations meet every claim.
- “Private repositories cannot be contaminated” is too strong if interpreted beyond model-training contamination. Eval-time leakage through Git history, workspaces, tests, caches, and network access remains possible.
- LLM-based equivalence and review scores should remain secondary signals because they are themselves model-dependent measurements.
- A universal schema or signed receipt is only a moat after independent adoption; it begins as an interoperability experiment.

## Recommended operating thesis

Treat this repository as a **90-day learning instrument with milestone gates**, not a stealth product build. The first valuable result is evidence that a falsification harness catches known-invalid tasks for the correct reasons. The second is evidence that one narrow schema or validation primitive integrates cleanly with at least two existing ecosystems.

Stop if the work expands toward a dashboard, automatic optimization, or a full runner before those gates pass.

## Sources

- [Stet product](https://www.stet.sh/)
- [Stet methodology](https://www.stet.sh/methodology)
- [OpenAI benchmark audit](https://openai.com/index/separating-signal-from-noise-coding-evaluations/)
- [SWE-smith repository](https://github.com/SWE-bench/SWE-smith)
