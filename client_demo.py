"""End-to-end stdio MCP client demonstration for CyberLaw MCP Server."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _send(proc: subprocess.Popen[str], payload: dict[str, object]) -> dict[str, object] | None:
    assert proc.stdin is not None
    assert proc.stdout is not None
    proc.stdin.write(json.dumps(payload, ensure_ascii=False) + "\n")
    proc.stdin.flush()
    if "id" not in payload:
        return None
    line = proc.stdout.readline()
    return json.loads(line)


def main() -> None:
    project_dir = Path(__file__).resolve().parent
    proc = subprocess.Popen(
        [sys.executable, "-m", "cyberlaw_mcp.server", "--root", str(project_dir)],
        cwd=str(project_dir),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    try:
        init_resp = _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"clientInfo": {"name": "portfolio-demo", "version": "1.0"}},
            },
        )
        print("1. Initialize:", json.dumps(init_resp["result"]["serverInfo"], ensure_ascii=False))
        _send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized"})

        tools_resp = _send(proc, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tool_names = [t["name"] for t in tools_resp["result"]["tools"]]
        print("2. Tools available:", tool_names)

        res_resp = _send(proc, {"jsonrpc": "2.0", "id": 3, "method": "resources/list"})
        res_uris = [r["uri"] for r in res_resp["result"]["resources"]]
        print("3. Resources available:", res_uris)

        audit_resp = _send(
            proc,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "check_file_compliance",
                    "arguments": {"file_path": "sample_prompt.txt", "jurisdiction": "UZ+GDPR"},
                },
            },
        )
        audit_data = json.loads(audit_resp["result"]["content"][0]["text"])
        print(
            f"4. Audit status: {audit_data['status']} | Score: {audit_data['score']}/100 | "
            f"Findings: {audit_data['pii_summary']['findings_count']}"
        )
        print("5. Redacted preview:\n" + audit_data["redacted_preview"])
    finally:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)


if __name__ == "__main__":
    main()
