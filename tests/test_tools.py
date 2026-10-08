"""
Unit tests for the IPC Cleaner Agent capability tools.
"""

import unittest
from ipc_cleaner.core.syscalls import libc_create_shm, libc_shmctl_rmid
from ipc_cleaner.tools.audit import (
    audit_ipc_leaks,
    get_ipc_summary,
    inspect_ipc_resource,
    list_ipc_resources,
)
from ipc_cleaner.tools.cleaner import (
    purge_abandoned_ipc,
    purge_shared_memory,
)


class TestTools(unittest.TestCase):

    def test_list_ipc_resources(self):
        res = list_ipc_resources("all")
        self.assertEqual(res["status"], "success")
        self.assertIn("shared_memory", res)
        self.assertIn("total_shm_bytes", res)

    def test_get_ipc_summary(self):
        res = get_ipc_summary()
        self.assertEqual(res["status"], "success")
        self.assertIn("shared_memory", res)
        self.assertIn("semaphores", res)

    def test_audit_ipc_leaks(self):
        res = audit_ipc_leaks()
        self.assertIn("abandoned_shm_count", res)
        self.assertIn("reclaimable_ram_bytes", res)
        self.assertIn("reclaimable_ram_human", res)

    def test_safety_check_prevents_active_segment_purge(self):
        # Find active segments (like postgres with nattch > 0)
        res = list_ipc_resources("shm")
        active = [s for s in res.get("shared_memory", []) if s.get("nattch", 0) > 0]
        if active:
            active_id = active[0]["id"]
            # Purge without force MUST fail or refuse
            purge_res = purge_shared_memory([active_id], force=False)
            self.assertIn(active_id, purge_res["failed_ids"])
            self.assertIn("Refusing to purge", purge_res["failed_ids"][active_id])

    def test_dry_run_does_not_destroy_segment(self):
        # Create a temporary segment
        shmid, _ = libc_create_shm(size_bytes=8192)
        try:
            dry_res = purge_shared_memory([shmid], dry_run=True)
            self.assertTrue(dry_res["dry_run"])
            self.assertIn(shmid, dry_res["purged_ids"])
            self.assertEqual(dry_res["reclaimed_bytes"], 8192)

            # Segment should still exist!
            inspect_res = inspect_ipc_resource("shm", shmid)
            self.assertEqual(inspect_res["status"], "success")
        finally:
            libc_shmctl_rmid(shmid)


if __name__ == "__main__":
    unittest.main()
