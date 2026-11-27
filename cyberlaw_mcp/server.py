"""Pure-Python JSON-RPC 2.0 over stdio Model Context Protocol (MCP) server."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cyberlaw_mcp import __version__
from cyberlaw_mcp.compliance import (
    OWASP_LLM_RESOURCE,
    UZ_PERSONAL_DATA_RESOURCE,
    audit_prompt_compliance,
    extract_file_text,
)
from cyberlaw_mcp.scanner import redact_text, scan_text

PROTOCOL_VERSION = "2024-11-05"

TOOLS_SPEC: list[dict[str, Any]] = [
    {
        "name": "scan_pii",
        "description": "Detect PII (email, +998 phone, PINFL, passport, Luhn credit card) and secrets (API keys, JWT).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan for sensitive data."},
            },
            "required": ["text"],
        },
    },
    {
        "name": "redact_pii",
        "description": "Replace detected PII and credentials with deterministic placeholders like [EMAIL_1].",
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to redact before sending to an LLM."},
            },
            "required": ["text"],
        },
    },
    {
        "name": "audit_ai_prompt_compliance",
        "description": "Audit an AI prompt for PII exposure, prompt-injection signals, and UZ/GDPR compliance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string", "description": "Prompt text to audit."},
                "jurisdiction": {
                    "type": "string",
                    "description": "Regulatory baseline (e.g., UZ+GDPR).",
                    "default": "UZ+GDPR",
                },
                "stores_logs": {
                    "type": "boolean",
                    "description": "Whether raw prompts are stored in persistent logs.",
                    "default": False,
                },
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "check_file_compliance",
        "description": "Inspect a workspace file (.txt, .md, .json, .csv, .py, .pdf) for PII and compliance.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Path inside the allowed workspace root."},
                "jurisdiction": {"type": "string", "default": "UZ+GDPR"},
            },
            "required": ["file_path"],
        },
    },
]

RESOURCES_SPEC: list[dict[str, str]] = [
    {
        "uri": "compliance://checklists/uz-personal-data",
        "name": "Uzbekistan Personal Data & AI Compliance Checklist",
        "mimeType": "text/markdown",
        "description": "Core obligations under Law LRU-547 for AI applications.",
    },
    {
        "uri": "compliance://checklists/llm-security-owasp",
        "name": "OWASP LLM Top 10 Quick Guardrails",
        "mimeType": "text/markdown",
        "description": "Essential security controls for LLM tool-calling pipelines.",
    },
]


class MCPServer:
    """Stateful handler for MCP JSON-RPC 2.0 requests."""

    def __init__(self, allowed_root: Path | None = None) -> None:
        self.allowed_root = (allowed_root or Path.cwd()).resolve()

    def _call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        try:
            if name == "scan_pii":
                text = str(arguments["text"])
                return scan_text(text).to_dict(), False
            if name == "redact_pii":
                text = str(arguments["text"])
                return redact_text(text), False
            if name == "audit_ai_prompt_compliance":
                prompt = str(arguments["prompt"])
                jurisdiction = str(arguments.get("jurisdiction", "UZ+GDPR"))
                stores_logs = bool(arguments.get("stores_logs", False))
                return audit_prompt_compliance(prompt, jurisdiction=jurisdiction, stores_logs=stores_logs), False
            if name == "check_file_compliance":
                file_path = str(arguments["file_path"])
                jurisdiction = str(arguments.get("jurisdiction", "UZ+GDPR"))
                extracted = extract_file_text(file_path, self.allowed_root)
                audit = audit_prompt_compliance(extracted, jurisdiction=jurisdiction)
                audit["file_path"] = file_path
                return audit, False
            return {"error": f"Unknown tool: {name}"}, True
        except (KeyError, PermissionError, FileNotFoundError, ValueError) as exc:
            return {"error": str(exc)}, True

    def handle_request(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC 2.0 request or notification."""
        req_id = message.get("id")
        method = message.get("method", "")
        params = message.get("params") or {}

        # Notifications have no id and expect no response.
        if req_id is None:
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}, "resources": {}},
                    "serverInfo": {"name": "cyberlaw-mcp-server", "version": __version__},
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS_SPEC}}

        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments") or {}
            payload, is_error = self._call_tool(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                    "isError": is_error,
                },
            }

        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": RESOURCES_SPEC}}

        if method == "resources/read":
            uri = params.get("uri", "")
            resource_map = {
                "compliance://checklists/uz-personal-data": UZ_PERSONAL_DATA_RESOURCE,
                "compliance://checklists/llm-security-owasp": OWASP_LLM_RESOURCE,
            }
            if uri not in resource_map:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Unknown resource URI: {uri}"},
                }
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {"uri": uri, "mimeType": "text/markdown", "text": resource_map[uri]}
                    ]
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }


def serve_stdio(allowed_root: Path) -> None:
    """Read newline-delimited JSON-RPC messages from stdin and respond on stdout."""
    server = MCPServer(allowed_root=allowed_root)
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            err = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }
            sys.stdout.write(json.dumps(err, ensure_ascii=False) + "\n")
            sys.stdout.flush()
            continue

        response = server.handle_request(message)
        if response is not None:
            sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
            sys.stdout.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberLaw MCP Server (JSON-RPC 2.0 stdio)")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Allowed workspace root directory")
    args = parser.parse_args()
    sys.stderr.write(f"[cyberlaw-mcp] listening on stdio (root={args.root.resolve()})\n")
    sys.stderr.flush()
    serve_stdio(args.root)


if __name__ == "__main__":
    main()
