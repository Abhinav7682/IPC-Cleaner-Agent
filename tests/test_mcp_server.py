"""
Unit and integration tests for the Model Context Protocol (MCP) server.
Validates initialize, tools/list, tools/call, resources/list, resources/read,
prompts/list, and prompts/get across both the standalone JSON-RPC dispatcher
and the official MCP SDK server.
"""

import json
import unittest
from ipc_cleaner.mcp_server import (
    StandaloneJsonRpcMcpServer,
    create_mcp_app,
    get_mcp_tool_definitions,
)


class TestMCPServer(unittest.TestCase):

    def setUp(self):
        self.server = StandaloneJsonRpcMcpServer()

    def test_initialize_handshake(self):
        """Validates MCP protocol initialization and capabilities exchange."""
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        res = self.server.handle_request(req)
        self.assertIsNotNone(res)
        self.assertEqual(res["id"], 1)
        self.assertEqual(res["jsonrpc"], "2.0")

        result = res["result"]
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertEqual(result["serverInfo"]["name"], "ipc-cleaner-agent")
        self.assertIn("tools", result["capabilities"])
        self.assertIn("resources", result["capabilities"])
        self.assertIn("prompts", result["capabilities"])

    def test_ping(self):
        """Validates MCP ping heartbeat."""
        req = {"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {}}
        res = self.server.handle_request(req)
        self.assertEqual(res["result"], {})

    def test_tools_list(self):
        """Validates that all 9 IPC cleaner tools are exposed in tools/list."""
        req = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
        res = self.server.handle_request(req)
        tools = res["result"]["tools"]
        self.assertEqual(len(tools), 9)

        tool_names = [t["name"] for t in tools]
        expected = [
            "list_ipc_resources",
            "audit_ipc_leaks",
            "get_ipc_summary",
            "inspect_ipc_resource",
            "purge_shared_memory",
            "purge_message_queues",
            "purge_semaphores",
            "purge_abandoned_ipc",
            "simulate_ipc_leak",
        ]
        for exp in expected:
            self.assertIn(exp, tool_names)

        # Check inputSchema validity
        for t in tools:
            self.assertIn("inputSchema", t)
            self.assertEqual(t["inputSchema"]["type"], "object")

    def test_tools_call_get_ipc_summary(self):
        """Validates executing tools/call for get_ipc_summary."""
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "get_ipc_summary", "arguments": {}}
        }
        res = self.server.handle_request(req)
        self.assertFalse(res["result"]["isError"])
        content = res["result"]["content"]
        self.assertEqual(len(content), 1)
        self.assertEqual(content[0]["type"], "text")
        data = json.loads(content[0]["text"])
        self.assertEqual(data["status"], "success")
        self.assertIn("shared_memory", data)
        self.assertIn("message_queues", data)
        self.assertIn("semaphores", data)

    def test_tools_call_unknown_tool(self):
        """Validates error response when calling an unknown tool."""
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {"name": "non_existent_tool", "arguments": {}}
        }
        res = self.server.handle_request(req)
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32601)

    def test_resources_list_and_read(self):
        """Validates reading exposed MCP resources."""
        # List resources
        req_list = {"jsonrpc": "2.0", "id": 6, "method": "resources/list", "params": {}}
        res_list = self.server.handle_request(req_list)
        resources = res_list["result"]["resources"]
        self.assertGreaterEqual(len(resources), 4)

        uris = [r["uri"] for r in resources]
        self.assertIn("ipc://summary", uris)
        self.assertIn("ipc://procfs/shm", uris)

        # Read resource
        req_read = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "resources/read",
            "params": {"uri": "ipc://summary"}
        }
        res_read = self.server.handle_request(req_read)
        contents = res_read["result"]["contents"]
        self.assertEqual(contents[0]["uri"], "ipc://summary")
        parsed = json.loads(contents[0]["text"])
        self.assertEqual(parsed["status"], "success")

    def test_prompts_list_and_get(self):
        """Validates retrieving predefined MCP prompts."""
        req_list = {"jsonrpc": "2.0", "id": 8, "method": "prompts/list", "params": {}}
        res_list = self.server.handle_request(req_list)
        prompts = res_list["result"]["prompts"]
        self.assertGreaterEqual(len(prompts), 2)

        # Get prompt
        req_get = {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "prompts/get",
            "params": {"name": "audit_and_remediate_leaks", "arguments": {"resource_type": "all"}}
        }
        res_get = self.server.handle_request(req_get)
        messages = res_get["result"]["messages"]
        self.assertGreaterEqual(len(messages), 1)
        self.assertIn("audit_ipc_leaks", messages[0]["content"]["text"])

    def test_official_sdk_app_initialization(self):
        """Validates that create_mcp_app initializes cleanly if mcp package is installed."""
        app = create_mcp_app()
        # On environments with mcp installed, app is not None
        if app is not None:
            self.assertEqual(app.name, "ipc-cleaner-agent")


if __name__ == "__main__":
    unittest.main()
