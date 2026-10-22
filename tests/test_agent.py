"""
Unit tests for the IPCCleanerAgent and intent routing.
"""

import unittest
from ipc_cleaner.agent import IPCCleanerAgent


class TestAgent(unittest.TestCase):

    def setUp(self):
        self.agent = IPCCleanerAgent()

    def test_clean_abandoned_prompt_routing(self):
        result = self.agent.handle_query("Clean up any abandoned shared memory segments taking up RAM.")
        self.assertEqual(result["agent"], "ipc_cleaner")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("purge_abandoned_ipc", tool_names)
        self.assertIn("CLEANUP", result["response"])

    def test_dry_run_prompt_routing(self):
        result = self.agent.handle_query("Dry run cleanup of abandoned shared memory segments")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("purge_abandoned_ipc", tool_names)
        self.assertTrue(result["tool_calls"][0]["arguments"].get("dry_run", False))
        self.assertIn("DRY RUN", result["response"])

    def test_audit_prompt_routing(self):
        result = self.agent.handle_query("Audit IPC resources for memory leaks")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("audit_ipc_leaks", tool_names)
        self.assertIn("AUDIT REPORT", result["response"])

    def test_list_prompt_routing(self):
        result = self.agent.handle_query("List active shared memory resources")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("list_ipc_resources", tool_names)
        self.assertIn("ACTIVE IPC RESOURCES", result["response"])

    def test_sem_and_msg_routing(self):
        result = self.agent.handle_query("Audit semaphores and message queues for leaks")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("audit_ipc_leaks", tool_names)
        self.assertEqual(result["tool_calls"][0]["arguments"].get("resource_type"), "all")

    def test_clean_semaphores_routing(self):
        result = self.agent.handle_query("Clean up abandoned semaphores")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("purge_abandoned_ipc", tool_names)
        self.assertEqual(result["tool_calls"][0]["arguments"].get("resource_type"), "sem")

    def test_list_message_queues_routing(self):
        result = self.agent.handle_query("List active message queues")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("list_ipc_resources", tool_names)
        self.assertEqual(result["tool_calls"][0]["arguments"].get("resource_type"), "msg")

    def test_summary_prompt_routing(self):
        result = self.agent.handle_query("Get IPC subsystem summary")
        tool_names = [tc["tool"] for tc in result["tool_calls"]]
        self.assertIn("get_ipc_summary", tool_names)
        self.assertIn("IPC SUBSYSTEM SUMMARY", result["response"])


if __name__ == "__main__":
    unittest.main()
