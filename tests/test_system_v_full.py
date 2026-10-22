"""
Comprehensive test suite for Full System V IPC coverage:
Shared Memory, Semaphores, and Message Queues.
Validates procfs parsers, waiter safety locks, dead PID heuristics,
direct libc system calls, and full multi-resource remediation.
"""

import sys
import unittest
from unittest.mock import patch

from ipc_cleaner.agent import IPCCleanerAgent
from ipc_cleaner.core.executor import IPCExecutor
from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.core.syscalls import (
    libc_create_msg,
    libc_create_sem,
    libc_msgctl_rmid,
    libc_semctl_get_stats,
    libc_semctl_rmid,
)
from ipc_cleaner.models import LeakConfidence, MessageQueue, SemaphoreSet
from ipc_cleaner.tools.audit import audit_ipc_leaks, list_ipc_resources
from ipc_cleaner.tools.cleaner import purge_abandoned_ipc, purge_message_queues, purge_semaphores
from ipc_cleaner.tools.simulator import simulate_ipc_leak

# Sample procfs mock fixtures
MOCK_PROC_MSG = """       key      msqid perms                  cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime
         0     131072   600                       0          0     0     0  1000  1000  1000  1000          0          0 1729600000
    123456     262144   666                    1024          5   500   500  1000  1000  1000  1000 1729600000 1729600000 1729600000
"""

MOCK_PROC_SEM = """       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime
         0      65536   600          1  1000  1000  1000  1000          0 1729600000
    789012     131072   666          4  1000  1000  1000  1000 1729600000 1729600000
"""


class TestSystemVFull(unittest.TestCase):

    def test_mock_proc_sysvipc_msg_parsing(self):
        """Validates parsing of Linux /proc/sysvipc/msg."""
        queues = IPCParser.parse_proc_sysvipc_msg(MOCK_PROC_MSG)
        self.assertEqual(len(queues), 2)

        q1 = queues[0]
        self.assertEqual(q1.id, 131072)
        self.assertEqual(q1.messages, 0)
        self.assertEqual(q1.used_bytes, 0)
        self.assertEqual(q1.owner, "1000")

        q2 = queues[1]
        self.assertEqual(q2.id, 262144)
        self.assertEqual(q2.messages, 5)
        self.assertEqual(q2.used_bytes, 1024)

    def test_mock_proc_sysvipc_sem_parsing(self):
        """Validates parsing of Linux /proc/sysvipc/sem."""
        sems = IPCParser.parse_proc_sysvipc_sem(MOCK_PROC_SEM)
        self.assertEqual(len(sems), 2)

        s1 = sems[0]
        self.assertEqual(s1.id, 65536)
        self.assertEqual(s1.nsems, 1)
        self.assertEqual(s1.owner, "1000")

        s2 = sems[1]
        self.assertEqual(s2.id, 131072)
        self.assertEqual(s2.nsems, 4)

    def test_semaphore_waiter_lock_prevents_purge(self):
        """Ensures that a semaphore with active waiting processes is never purged without force."""
        sem = SemaphoreSet(
            id=9999,
            key="0x0",
            owner="root",
            perms="600",
            nsems=1,
            nwaiters=3,  # Active waiters waiting on semaphore
            is_abandoned=False,
            leak_confidence=LeakConfidence.NONE,
        )
        # Attempt to purge via executor
        res = IPCExecutor.remove_sem_single(9999, sem_info=sem, force=False)
        self.assertFalse(res[0], "Purge should have been blocked by active waiter lock")
        self.assertIn("active waiting processes", res[1])

        # Overridden when force=True
        # (will fail with OS syscall error in dry-run or mock, but safety check was bypassed)
        dry_res = IPCExecutor.remove_sem_single(9999, sem_info=sem, force=True, dry_run=True)
        self.assertTrue(dry_res[0])

    def test_message_queue_messages_lock_prevents_purge(self):
        """Ensures that a message queue containing unread messages is protected unless force is given."""
        msg = MessageQueue(
            id=8888,
            key="0x0",
            owner="root",
            perms="600",
            used_bytes=2048,
            messages=10,  # 10 buffered messages!
            is_abandoned=False,
            leak_confidence=LeakConfidence.NONE,
        )
        res = IPCExecutor.remove_msg_single(8888, msg_info=msg, force=False)
        self.assertFalse(res[0], "Purge should have been blocked because messages exist")
        self.assertIn("unread messages", res[2])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Live Linux System V kernel required")
    def test_live_semctl_get_stats(self):
        """Validates real-time libc semctl GETPID, GETNCNT, and GETZCNT queries."""
        semid, err = libc_create_sem(nsems=1)
        self.assertIsNone(err)
        self.assertIsNotNone(semid)
        try:
            last_pid, ncnt, zcnt = libc_semctl_get_stats(semid, semnum=0)
            self.assertEqual(ncnt, 0)
            self.assertEqual(zcnt, 0)
            # Newly created un-operated semaphore has no last PID
            self.assertIsNone(last_pid)
        finally:
            libc_semctl_rmid(semid)

    @unittest.skipUnless(sys.platform.startswith("linux"), "Live Linux System V kernel required")
    def test_multi_resource_e2e_lifecycle(self):
        """
        Full End-to-End Lifecycle test for all 3 System V resource types:
        1. Simulate 1 SHM, 1 SEM, 1 MSG leak with terminating creator process.
        2. Audit and verify all 3 are detected as abandoned leaks.
        3. Purge all 3 via purge_abandoned_ipc(resource_type='all').
        4. Confirm complete kernel reclamation.
        """
        agent = IPCCleanerAgent()

        # Step 1: Simulate leaks across all 3 subsystems
        sim = simulate_ipc_leak(shm_count=1, size_bytes=262144, sem_count=1, msg_count=1)
        self.assertEqual(sim["status"], "success")

        created_shm = sim.get("created_shm_ids", [])
        created_sem = sim.get("created_sem_ids", [])
        created_msg = sim.get("created_msg_ids", [])

        self.assertEqual(len(created_shm), 1)
        self.assertEqual(len(created_sem), 1)
        self.assertEqual(len(created_msg), 1)

        shmid = created_shm[0]
        semid = created_sem[0]
        msqid = created_msg[0]

        try:
            # Step 2: Audit leaks
            audit_res = audit_ipc_leaks(resource_type="all")
            found_shm = [s for s in audit_res.get("abandoned_shm", []) if s["id"] == shmid]
            found_sem = [s for s in audit_res.get("abandoned_sem", []) if s["id"] == semid]
            found_msg = [m for m in audit_res.get("abandoned_msg", []) if m["id"] == msqid]

            self.assertEqual(len(found_shm), 1, f"SHM {shmid} should be detected as abandoned")
            self.assertEqual(len(found_sem), 1, f"SEM {semid} should be detected as abandoned")
            self.assertEqual(len(found_msg), 1, f"MSG {msqid} should be detected as abandoned")

            # Step 3: Natural language purge of all abandoned IPC via Agent
            res = agent.handle_query("Clean up all abandoned IPC resources")
            self.assertIn("CLEANUP COMPLETE", res["response"])
            self.assertIn(str(shmid), res["response"])
            self.assertIn(str(semid), res["response"])
            self.assertIn(str(msqid), res["response"])

            # Step 4: Verify complete kernel cleanup
            all_shm, all_msg, all_sem = IPCParser.fetch_all()
            self.assertNotIn(shmid, [s.id for s in all_shm])
            self.assertNotIn(semid, [s.id for s in all_sem])
            self.assertNotIn(msqid, [m.id for m in all_msg])

        except Exception as e:
            # Cleanup in case of assertion failure
            from ipc_cleaner.core.syscalls import libc_shmctl_rmid
            libc_shmctl_rmid(shmid)
            libc_semctl_rmid(semid)
            libc_msgctl_rmid(msqid)
            raise e


if __name__ == "__main__":
    unittest.main()
