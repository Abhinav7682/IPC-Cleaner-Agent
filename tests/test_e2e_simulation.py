"""
End-to-End integration test simulating orphaned IPC memory leaks,
auditing them via the agent, and autonomously purging them.
"""

import unittest
from ipc_cleaner.agent import IPCCleanerAgent
from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.tools.simulator import simulate_ipc_leak


class TestE2ESimulation(unittest.TestCase):

    def test_e2e_leak_and_remediation_lifecycle(self):
        agent = IPCCleanerAgent()

        # 1. Simulate 2 leaked segments of 512KB (524288 bytes) each
        size_bytes = 524288
        sim_res = simulate_ipc_leak(shm_count=2, size_bytes=size_bytes)
        self.assertEqual(sim_res["status"], "success")
        created_ids = sim_res["created_shm_ids"]
        self.assertEqual(len(created_ids), 2)

        # 2. Verify segments exist in system and are detected as abandoned
        all_shm, _, _ = IPCParser.fetch_all()
        found_ids = [s.id for s in all_shm if s.id in created_ids]
        self.assertEqual(len(found_ids), 2)

        for s in all_shm:
            if s.id in created_ids:
                self.assertEqual(s.nattch, 0)
                self.assertTrue(s.is_abandoned)

        # 3. Dry-run prompt via Agent
        dry_result = agent.handle_query("Dry run cleanup of abandoned shared memory segments")
        self.assertIn("DRY RUN", dry_result["response"])
        for cid in created_ids:
            self.assertIn(str(cid), dry_result["response"])

        # 4. Autonomous Purge prompt via Agent
        # The prompt from assignment: "Clean up any abandoned shared memory segments taking up RAM."
        clean_result = agent.handle_query("Clean up any abandoned shared memory segments taking up RAM.")
        self.assertIn("CLEANUP COMPLETE", clean_result["response"])
        for cid in created_ids:
            self.assertIn(str(cid), clean_result["response"])

        # 5. Verify the segments are completely removed from the OS
        all_shm_after, _, _ = IPCParser.fetch_all()
        after_ids = [s.id for s in all_shm_after if s.id in created_ids]
        self.assertEqual(len(after_ids), 0, f"Segments still lingering after purge: {after_ids}")


if __name__ == "__main__":
    unittest.main()
