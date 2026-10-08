"""
Unit tests for the Universal IPC Parser (Linux and Darwin/BSD fixtures).
"""

import unittest
from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.models import LeakConfidence


LINUX_IPCS_OUTPUT = """
------ Message Queues --------
key        msqid      owner      perms      used-bytes   messages    
0x00010000 100        user       600        0            0           

------ Shared Memory Segments --------
key        shmid      owner      perms      bytes      nattch     status      
0x00000000 32768      postgres   600        524288     4                      
0x00000001 65536      www-data   600        1048576    0          dest
0x00000002 98304      nobody     666        2097152    0                      

------ Semaphore Arrays --------
key        semid      owner      perms      nsems     
0x00001234 11111      postgres   600        17        
"""

DARWIN_IPCS_OUTPUT = """
IPC status from <running system> as of Thu Oct  8 15:21:26 IST 2026
T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP CBYTES  QNUM QBYTES LSPID LRPID   STIME    RTIME    CTIME
Message Queues:

T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP NATTCH  SEGSZ  CPID  LPID   ATIME    DTIME    CTIME
Shared Memory:
m  65536 0x009d3bc6 --rw------- postgres   daemon postgres   daemon      9     56    567    567 10:40:41 15:21:24 10:40:41
m 131072 0x00000000 --rw------- www-data   daemon www-data   daemon      0 1048576  99999      0 10:40:41 15:21:24 10:40:41

T     ID     KEY        MODE       OWNER    GROUP  CREATOR   CGROUP NSEMS   OTIME    CTIME
Semaphores:
s  65536 0x009d3bc7 --ra------- postgres   daemon postgres   daemon     17 10:40:41 10:40:41
"""


class TestIPCParser(unittest.TestCase):

    def test_parse_linux_ipcs(self):
        pid_map = {
            32768: (500, 500),
            65536: (99999, 99999),  # 99999 is dead PID
            98304: (99999, 99999)
        }
        shm, msg, sem = IPCParser.parse_ipcs_output(LINUX_IPCS_OUTPUT, pid_map=pid_map)

        self.assertEqual(len(shm), 3)
        self.assertEqual(len(msg), 1)
        self.assertEqual(len(sem), 1)

        # Segment 32768 has 4 attachments -> NOT abandoned
        seg_active = [s for s in shm if s.id == 32768][0]
        self.assertEqual(seg_active.nattch, 4)
        self.assertFalse(seg_active.is_abandoned)
        self.assertEqual(seg_active.leak_confidence, LeakConfidence.NONE)

        # Segment 65536 has 0 attachments and dest flag -> HIGH leak confidence
        seg_dest = [s for s in shm if s.id == 65536][0]
        self.assertEqual(seg_dest.nattch, 0)
        self.assertTrue(seg_dest.is_abandoned)
        self.assertEqual(seg_dest.leak_confidence, LeakConfidence.HIGH)
        self.assertIn("dest", seg_dest.status)

        # Segment 98304 has 0 attachments and dead PID -> HIGH leak confidence
        seg_dead = [s for s in shm if s.id == 98304][0]
        self.assertEqual(seg_dead.nattch, 0)
        self.assertTrue(seg_dead.is_abandoned)

    def test_parse_darwin_ipcs(self):
        shm, msg, sem = IPCParser.parse_ipcs_output(DARWIN_IPCS_OUTPUT)

        self.assertEqual(len(shm), 2)
        self.assertEqual(len(sem), 1)

        # Active segment
        seg_active = [s for s in shm if s.id == 65536][0]
        self.assertEqual(seg_active.nattch, 9)
        self.assertFalse(seg_active.is_abandoned)

        # Abandoned segment
        seg_abandoned = [s for s in shm if s.id == 131072][0]
        self.assertEqual(seg_abandoned.nattch, 0)
        self.assertEqual(seg_abandoned.bytes, 1048576)
        self.assertTrue(seg_abandoned.is_abandoned)


if __name__ == "__main__":
    unittest.main()
