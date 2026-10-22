"""
Model Context Protocol (MCP) Server for IPC Cleaner Agent.
Exposes Linux System V IPC audit, listing, inspection, simulation, and remediation tools
over stdio JSON-RPC for Claude Desktop, Cursor, Antigravity IDE, and other MCP clients.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional

# Ensure repository root is in sys.path
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

from ipc_cleaner.llm.schemas import TOOL_SCHEMAS
from ipc_cleaner.tools.audit import (
    audit_ipc_leaks,
    get_ipc_summary,
    inspect_ipc_resource,
    list_ipc_resources,
)
from ipc_cleaner.tools.cleaner import (
    purge_abandoned_ipc,
    purge_message_queues,
    purge_semaphores,
    purge_shared_memory,
)
from ipc_cleaner.tools.simulator import simulate_ipc_leak

SERVER_NAME = "ipc-cleaner-agent"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

# Map tool names to actual callables
TOOL_DISPATCH: Dict[str, Any] = {
    "list_ipc_resources": list_ipc_resources,
    "audit_ipc_leaks": audit_ipc_leaks,
    "get_ipc_summary": get_ipc_summary,
    "inspect_ipc_resource": inspect_ipc_resource,
    "purge_shared_memory": purge_shared_memory,
    "purge_message_queues": purge_message_queues,
    "purge_semaphores": purge_semaphores,
    "purge_abandoned_ipc": purge_abandoned_ipc,
    "simulate_ipc_leak": simulate_ipc_leak,
}

RESOURCES = [
    {
        "uri": "ipc://summary",
        "name": "IPC Subsystem Summary",
        "description": "High-level summary of active and leaked IPC resources across shm, sem, msg.",
        "mimeType": "application/json",
    },
    {
        "uri": "ipc://procfs/shm",
        "name": "Procfs Shared Memory Table",
        "description": "Raw contents of Linux /proc/sysvipc/shm virtual file.",
        "mimeType": "text/plain",
    },
    {
        "uri": "ipc://procfs/sem",
        "name": "Procfs Semaphores Table",
        "description": "Raw contents of Linux /proc/sysvipc/sem virtual file.",
        "mimeType": "text/plain",
    },
    {
        "uri": "ipc://procfs/msg",
        "name": "Procfs Message Queues Table",
        "description": "Raw contents of Linux /proc/sysvipc/msg virtual file.",
        "mimeType": "text/plain",
    },
]

PROMPTS = [
    {
        "name": "audit_and_remediate_leaks",
        "description": "Audits the OS for abandoned System V IPC resources and purges them if confirmed.",
        "arguments": [
            {
                "name": "resource_type",
                "description": "Type of resources to audit: 'all', 'shm', 'sem', or 'msg'",
                "required": False,
            }
        ],
    },
    {
        "name": "safe_dry_run_preview",
        "description": "Previews what IPC resources would be cleaned without altering system state.",
        "arguments": [],
    },
]


def read_procfs_content(path: str) -> str:
    """Safely reads a procfs virtual file if present."""
    if os.path.isfile(path):
        try:
            with open(path, "r") as f:
                return f.read()
        except Exception as e:
            return f"Error reading {path}: {e}"
    return f"Notice: {path} is not available on this host OS (Linux kernel required)."


def get_mcp_tool_definitions() -> List[Dict[str, Any]]:
    """Converts internal tool schemas to MCP standard tool definitions."""
    mcp_tools = []
    for s in TOOL_SCHEMAS:
        mcp_tools.append({
            "name": s["name"],
            "description": s["description"],
            "inputSchema": s.get("parameters", {"type": "object", "properties": {}}),
        })
    return mcp_tools


# ============================================================================
# 1. Native Official MCP SDK Integration (mcp 2.x / 1.x)
# ============================================================================

def create_mcp_app() -> Optional[Any]:
    """Initializes server using the official MCP Python SDK if available."""
    server = None
    try:
        from mcp.server.mcpserver import MCPServer
        server = MCPServer(SERVER_NAME)
    except ImportError:
        try:
            from mcp.server.fastmcp import FastMCP
            server = FastMCP(SERVER_NAME)
        except ImportError:
            return None

    # Register tools
    server.tool(name="list_ipc_resources", description="Lists active System V IPC resources (shm, msg, sem).")(list_ipc_resources)
    server.tool(name="audit_ipc_leaks", description="Audits OS for abandoned or leaked IPC resources.")(audit_ipc_leaks)
    server.tool(name="get_ipc_summary", description="Returns high-level statistics of IPC usage.")(get_ipc_summary)
    server.tool(name="inspect_ipc_resource", description="Inspects a specific IPC resource in deep detail.")(inspect_ipc_resource)
    server.tool(name="purge_shared_memory", description="Purges specified shared memory segment IDs.")(purge_shared_memory)
    server.tool(name="purge_semaphores", description="Purges specified semaphore sets.")(purge_semaphores)
    server.tool(name="purge_message_queues", description="Purges specified message queues.")(purge_message_queues)
    server.tool(name="purge_abandoned_ipc", description="Autonomously audits and purges abandoned System V IPC resources.")(purge_abandoned_ipc)
    server.tool(name="simulate_ipc_leak", description="Creates controlled orphaned IPC resources for testing.")(simulate_ipc_leak)

    # Register resources
    @server.resource("ipc://summary")
    def res_summary() -> str:
        return json.dumps(get_ipc_summary(), indent=2)

    @server.resource("ipc://procfs/shm")
    def res_proc_shm() -> str:
        return read_procfs_content("/proc/sysvipc/shm")

    @server.resource("ipc://procfs/sem")
    def res_proc_sem() -> str:
        return read_procfs_content("/proc/sysvipc/sem")

    @server.resource("ipc://procfs/msg")
    def res_proc_msg() -> str:
        return read_procfs_content("/proc/sysvipc/msg")

    # Register prompts
    @server.prompt("audit_and_remediate_leaks")
    def prompt_audit(resource_type: str = "all") -> str:
        return (
            f"Please run audit_ipc_leaks(resource_type='{resource_type}') to detect any abandoned resources. "
            f"If abandoned resources with zero attachments and dead creator processes are detected, "
            f"preview them with dry_run=True, then invoke purge_abandoned_ipc(resource_type='{resource_type}') to reclaim RAM."
        )

    @server.prompt("safe_dry_run_preview")
    def prompt_dry_run() -> str:
        return (
            "Please invoke purge_abandoned_ipc(dry_run=True) to safely inspect and calculate "
            "how much physical RAM can be reclaimed without modifying system state."
        )

    return server


# ============================================================================
# 2. Pure-Python JSON-RPC 2.0 stdio Server (Zero Dependency Fallback)
# ============================================================================

class StandaloneJsonRpcMcpServer:
    """
    Standard-compliant JSON-RPC 2.0 stdio MCP server.
    Ensures 100% functionality even in minimal environments without the `mcp` package.
    """

    def __init__(self):
        self.tools = get_mcp_tool_definitions()

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        # Handle notifications (no response needed)
        if method == "notifications/initialized":
            return None

        # 1. initialize
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "prompts": {"listChanged": False},
                    },
                    "serverInfo": {
                        "name": SERVER_NAME,
                        "version": SERVER_VERSION,
                    },
                },
            }

        # 2. ping
        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        # 3. tools/list
        if method == "tools/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": self.tools},
            }

        # 4. tools/call
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments", {})
            if tool_name not in TOOL_DISPATCH:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Method/Tool '{tool_name}' not found",
                    },
                }

            func = TOOL_DISPATCH[tool_name]
            try:
                raw_result = func(**arguments)
                text_out = json.dumps(raw_result, indent=2)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_out}],
                        "isError": False,
                    },
                }
            except Exception as e:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Tool execution error: {str(e)}"}],
                        "isError": True,
                    },
                }

        # 5. resources/list
        if method == "resources/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": RESOURCES},
            }

        # 6. resources/read
        if method == "resources/read":
            uri = params.get("uri", "")
            content_text = ""
            if uri == "ipc://summary":
                content_text = json.dumps(get_ipc_summary(), indent=2)
            elif uri == "ipc://procfs/shm":
                content_text = read_procfs_content("/proc/sysvipc/shm")
            elif uri == "ipc://procfs/sem":
                content_text = read_procfs_content("/proc/sysvipc/sem")
            elif uri == "ipc://procfs/msg":
                content_text = read_procfs_content("/proc/sysvipc/msg")
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32002, "message": f"Resource URI '{uri}' not found"},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json" if uri.endswith("summary") else "text/plain",
                            "text": content_text,
                        }
                    ]
                },
            }

        # 7. prompts/list
        if method == "prompts/list":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"prompts": PROMPTS},
            }

        # 8. prompts/get
        if method == "prompts/get":
            pname = params.get("name")
            pargs = params.get("arguments", {})
            if pname == "audit_and_remediate_leaks":
                rtype = pargs.get("resource_type", "all")
                msg = (
                    f"Please run audit_ipc_leaks(resource_type='{rtype}') to detect any abandoned resources. "
                    f"If abandoned resources with zero attachments and dead creator processes are detected, "
                    f"preview them with dry_run=True, then invoke purge_abandoned_ipc(resource_type='{rtype}') to reclaim RAM."
                )
            elif pname == "safe_dry_run_preview":
                msg = (
                    "Please invoke purge_abandoned_ipc(dry_run=True) to safely inspect and calculate "
                    "how much physical RAM can be reclaimed without modifying system state."
                )
            else:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Prompt '{pname}' not found"},
                }

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": pname,
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": msg},
                        }
                    ],
                },
            }

        # Unknown method
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not supported"},
        }

    def run_stdio(self) -> None:
        """Reads JSON-RPC 2.0 lines from sys.stdin and writes to sys.stdout."""
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8")
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")

        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle_request(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp) + "\n")
                    sys.stdout.flush()
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()


# ============================================================================
# Main Entry Point
# ============================================================================

def main() -> None:
    """Runs the MCP server over stdio."""
    use_standalone = "--standalone" in sys.argv or "--jsonrpc" in sys.argv

    if not use_standalone:
        app = create_mcp_app()
        if app is not None:
            # Run via official MCP SDK
            app.run(transport="stdio")
            return

    # Fallback to standalone JSON-RPC 2.0 stdio server
    server = StandaloneJsonRpcMcpServer()
    server.run_stdio()


if __name__ == "__main__":
    main()
