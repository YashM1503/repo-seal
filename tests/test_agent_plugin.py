from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any


class AgentPluginTests(unittest.TestCase):
    def _exchange(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        root = Path(__file__).resolve().parents[1]
        launcher = root / "plugins" / "reposeal-agent" / "scripts" / "launch-mcp"
        environment = os.environ.copy()
        environment["REPOSEAL_PYTHON"] = sys.executable
        input_text = "".join(json.dumps(message) + "\n" for message in messages)
        result = subprocess.run(
            [str(launcher)],
            input=input_text,
            capture_output=True,
            check=True,
            env=environment,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.stderr, "")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def test_mcp_server_lists_and_validates_evidence(self) -> None:
        root = Path(__file__).resolve().parents[1]
        responses = self._exchange(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"},
                },
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {
                        "name": "reposeal_validate_evidence",
                        "arguments": {"path": str(root / "examples" / "evidence.json")},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {
                        "name": "reposeal_validate_evidence",
                        "arguments": {
                            "path": str(root / "examples" / "evidence.json"),
                            "execute": True,
                        },
                    },
                },
            ]
        )

        self.assertEqual([response["id"] for response in responses], [1, 2, 3, 4])
        tool_names = {tool["name"] for tool in responses[1]["result"]["tools"]}
        self.assertEqual(
            tool_names,
            {"reposeal_explain_evidence", "reposeal_validate_evidence"},
        )
        tool_result = responses[2]["result"]
        self.assertFalse(tool_result["isError"])
        self.assertEqual(tool_result["structuredContent"]["decision"], "ELIGIBLE")
        self.assertTrue(responses[3]["result"]["isError"])
        self.assertIn(
            "unknown arguments",
            responses[3]["result"]["structuredContent"]["error"],
        )


if __name__ == "__main__":
    unittest.main()
