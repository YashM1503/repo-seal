"""Read-only Model Context Protocol server for RepoSeal."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from .evidence import validate_evidence_path
from .version import __version__

SERVER_NAME = "reposeal"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
MAX_MESSAGE_BYTES = 1024 * 1024
MAX_TOOL_RESULT_BYTES = 8 * 1024 * 1024

EVIDENCE_FIELDS = {
    "task_id": "Which benchmark task is this?",
    "base_fails": "Does the intended behavior fail before the fix?",
    "gold_passes": "Does the accepted fix pass the verifier?",
    "flake_rate": "Did repeated clean verifier runs disagree?",
    "oracle_artifacts": "Could the solver see a hidden test or accepted answer?",
    "future_history_accessible": "Could the solver recover the fix from later Git history?",
    "verifier_writable": "Could the solver change the trusted verifier?",
    "network_egress_observed": "Did outbound access work despite a deny policy?",
    "grader_tamper_vectors": "Could repository-controlled hooks influence grading?",
    "declared_requirements": "What behavior was disclosed to the solver?",
    "verified_requirements": "What behavior did the verifier actually enforce?",
    "rejected_valid_alternatives": "Did a reviewed alternative solution fail unfairly?",
    "broken_patch_passes": "How many known-broken solutions passed?",
    "broken_patch_trials": "How many known-broken solutions were tried?",
    "cache_leaks": "Did shared state expose an answer or oracle material?",
}

TOOLS = [
    {
        "name": "reposeal_validate_evidence",
        "description": (
            "Validate one RepoSeal evidence JSON file or a nonrecursive directory "
            "and return its deterministic ELIGIBLE or HOLD receipt."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Evidence JSON file or directory.",
                }
            },
            "required": ["path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "reposeal_explain_evidence",
        "description": (
            "Explain RepoSeal evidence fields and the limits of its decisions "
            "without reading or writing files."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]


def _required_string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _reject_unknown(arguments: dict[str, Any], allowed: set[str]) -> None:
    unknown = sorted(set(arguments) - allowed)
    if unknown:
        raise ValueError(f"unknown arguments: {', '.join(unknown)}")


def _tool_result(payload: dict[str, Any], is_error: bool = False) -> dict[str, Any]:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if len(rendered.encode("utf-8")) > MAX_TOOL_RESULT_BYTES:
        payload = {"error": "Tool result exceeds the 8 MiB MCP response limit"}
        rendered = json.dumps(payload, indent=2, sort_keys=True)
        is_error = True
    return {
        "content": [
            {
                "type": "text",
                "text": rendered,
            }
        ],
        "structuredContent": payload,
        "isError": is_error,
    }


def _call_tool(name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    if name == "reposeal_validate_evidence":
        _reject_unknown(arguments, {"path"})
        evidence_path = Path(_required_string(arguments, "path"))
        return _tool_result(validate_evidence_path(evidence_path).to_dict())

    if name == "reposeal_explain_evidence":
        if arguments:
            raise ValueError("reposeal_explain_evidence accepts no arguments")
        return _tool_result(
            {
                "decisions": {
                    "ELIGIBLE": "No supplied check produced a blocking finding.",
                    "HOLD": "At least one blocking finding requires investigation.",
                },
                "evidence_fields": EVIDENCE_FIELDS,
                "limits": [
                    "RepoSeal validates observations; it does not collect them.",
                    "ELIGIBLE is not a security certification.",
                    "RepoSeal does not execute agents or arbitrary repositories.",
                ],
            }
        )

    raise ValueError(f"Unknown tool: {name}")


def _rpc_error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def handle_message(message: Any) -> Optional[dict[str, Any]]:
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return _rpc_error(None, -32600, "Invalid Request")

    method = message.get("method")
    request_id = message.get("id")
    params = message.get("params", {})

    if isinstance(method, str) and method.startswith("notifications/"):
        return None
    if not isinstance(method, str):
        return _rpc_error(request_id, -32600, "Invalid Request")
    if not isinstance(params, dict):
        return _rpc_error(request_id, -32602, "Invalid params")

    result: dict[str, Any]
    if method == "initialize":
        requested_version = params.get("protocolVersion", DEFAULT_PROTOCOL_VERSION)
        if not isinstance(requested_version, str):
            requested_version = DEFAULT_PROTOCOL_VERSION
        result = {
            "protocolVersion": requested_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": __version__},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _rpc_error(request_id, -32602, "Invalid params")
        try:
            result = _call_tool(name, arguments)
        except Exception as exc:  # noqa: BLE001 - keep MCP failures inside tool results
            result = _tool_result(
                {"error": f"{type(exc).__name__}: {exc}"}, is_error=True
            )
    else:
        return _rpc_error(request_id, -32601, "Method not found")

    if "id" not in message:
        return None
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _write_message(message: dict[str, Any]) -> None:
    encoded = json.dumps(message, separators=(",", ":"), allow_nan=False)
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()


def main() -> int:
    while True:
        raw_line = sys.stdin.buffer.readline(MAX_MESSAGE_BYTES + 1)
        if not raw_line:
            return 0
        if len(raw_line) > MAX_MESSAGE_BYTES:
            _write_message(_rpc_error(None, -32700, "Message exceeds 1 MiB limit"))
            return 2
        if not raw_line.strip():
            continue
        try:
            message = json.loads(raw_line)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _write_message(_rpc_error(None, -32700, "Parse error"))
            continue
        response = handle_message(message)
        if response is not None:
            _write_message(response)


if __name__ == "__main__":
    raise SystemExit(main())
