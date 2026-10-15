"""
Unit tests for direct libc IPC System Calls.
"""

import sys
import unittest
from ipc_cleaner.core.syscalls import (
    libc_create_msg,
    libc_create_sem,
    libc_create_shm,
    libc_msgctl_rmid,
    libc_semctl_rmid,
    libc_shmctl_rmid,
)


class TestSyscalls(unittest.TestCase):

    @unittest.skipUnless(sys.platform.startswith("linux"), "System V IPC libc syscalls require Linux")
    def test_shm_create_and_destroy(self):
        shmid, err = libc_create_shm(size_bytes=4096)
        self.assertIsNone(err, f"libc_create_shm failed: {err}")
        self.assertIsNotNone(shmid)
        self.assertGreaterEqual(shmid, 0)

        # Destroy via libc_shmctl_rmid
        ok, rmid_err = libc_shmctl_rmid(shmid)
        self.assertTrue(ok, f"libc_shmctl_rmid failed: {rmid_err}")

    @unittest.skipUnless(sys.platform.startswith("linux"), "System V IPC libc syscalls require Linux")
    def test_sem_create_and_destroy(self):
        semid, err = libc_create_sem(nsems=1)
        self.assertIsNone(err, f"libc_create_sem failed: {err}")
        self.assertIsNotNone(semid)
        self.assertGreaterEqual(semid, 0)

        # Destroy via libc_semctl_rmid
        ok, rmid_err = libc_semctl_rmid(semid)
        self.assertTrue(ok, f"libc_semctl_rmid failed: {rmid_err}")

    @unittest.skipUnless(sys.platform.startswith("linux"), "System V IPC libc syscalls require Linux")
    def test_msg_create_and_destroy(self):
        msqid, err = libc_create_msg()
        self.assertIsNone(err, f"libc_create_msg failed: {err}")
        self.assertIsNotNone(msqid)
        self.assertGreaterEqual(msqid, 0)

        # Destroy via libc_msgctl_rmid
        ok, rmid_err = libc_msgctl_rmid(msqid)
        self.assertTrue(ok, f"libc_msgctl_rmid failed: {rmid_err}")



if __name__ == "__main__":
    unittest.main()
