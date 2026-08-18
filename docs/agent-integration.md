# Agent integration

RepoSeal includes an installable agent skill and a read-only Model Context
Protocol (MCP) server. The integration helps an agent validate and explain
coding-agent benchmark evidence without running an agent or repository.

## Install from a clone

Set up RepoSeal first so the MCP server can use its Python environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e .
export REPOSEAL_PYTHON="$PWD/.venv/bin/python"
```

Then register the GitHub marketplace and install the plugin:

```bash
codex plugin marketplace add YashM1503/repo-seal --ref main
codex plugin add reposeal-agent@reposeal-tools
```

For local development, replace `YashM1503/repo-seal --ref main` with the
absolute path to the clone.

Restart the client after installation. The plugin includes the
`validate-agent-benchmarks-with-reposeal` skill. It uses `REPOSEAL_PYTHON` when
set, then looks for a repository `.venv`, `reposeal-mcp` on `PATH`, or an
installed RepoSeal package in Python 3.9 or newer. The explicit variable is the
most predictable choice for a cached GitHub plugin.

## Read-only MCP tools

| Tool | Purpose | Executes agents or repositories? |
| --- | --- | --- |
| `reposeal_validate_evidence` | Validate one evidence JSON file or a nonrecursive directory and return its receipt. | No |
| `reposeal_explain_evidence` | Explain evidence fields and decision limits. | No |

The MCP server deliberately does not expose evidence-draft writes, controlled
replay, mock-agent replay, Docker probes, or arbitrary command execution. The
older research commands remain restricted to repository-owned fixtures and
controlled development probes.

## Verify the package

Run the repository checks before publishing:

```bash
python -m unittest tests.test_agent_plugin -v
python -m unittest discover -s tests -v
python -m build
```
