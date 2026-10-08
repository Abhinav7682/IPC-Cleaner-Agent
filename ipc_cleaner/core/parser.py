"""
Universal IPC Output Parser for System V and POSIX IPC resources.
Parses output from Linux util-linux ipcs, Darwin/BSD ipcs, and Linux /proc/sysvipc/.
"""

import os
import re
import subprocess
import platform
from typing import Dict, List, Optional, Tuple

from ipc_cleaner.models import (
    LeakConfidence,
    MessageQueue,
    SemaphoreSet,
    ShmSegment,
)
from ipc_cleaner.core.process import inspect_pid, is_pid_dead


class IPCParser:
    """Parses ipcs and /proc/sysvipc output across Linux and Unix platforms."""

    @staticmethod
    def run_ipcs(flags: str = "-a") -> str:
        """Executes the system ipcs command and returns stdout."""
        try:
            res = subprocess.run(
                ["ipcs", flags],
                capture_output=True,
                text=True,
                check=False
            )
            return res.stdout
        except FileNotFoundError:
            return ""

    @staticmethod
    def run_ipcs_pids() -> Dict[int, Tuple[Optional[int], Optional[int]]]:
        """Runs 'ipcs -m -p' (common on Linux) to map shmid -> (cpid, lpid)."""
        pid_map: Dict[int, Tuple[Optional[int], Optional[int]]] = {}
        try:
            res = subprocess.run(
                ["ipcs", "-m", "-p"],
                capture_output=True,
                text=True,
                check=False
            )
            lines = res.stdout.splitlines()
            header_found = False
            for line in lines:
                parts = line.split()
                if not parts:
                    continue
                if "shmid" in [p.lower() for p in parts] and "cpid" in [p.lower() for p in parts]:
                    header_found = True
                    continue
                if header_found and len(parts) >= 4 and parts[0].isdigit():
                    try:
                        shmid = int(parts[0])
                        cpid = int(parts[2]) if parts[2].isdigit() else None
                        lpid = int(parts[3]) if parts[3].isdigit() else None
                        pid_map[shmid] = (cpid, lpid)
                    except (ValueError, IndexError):
                        pass
        except Exception:
            pass
        return pid_map

    @classmethod
    def parse_proc_sysvipc_shm(cls) -> List[ShmSegment]:
        """Directly parses Linux /proc/sysvipc/shm virtual file if present."""
        proc_file = "/proc/sysvipc/shm"
        segments: List[ShmSegment] = []
        if not os.path.exists(proc_file):
            return segments

        try:
            with open(proc_file, "r") as f:
                lines = f.readlines()
            if len(lines) < 2:
                return segments

            # Header: key shmid perms size cpid lpid nattch uid gid cuid cgid atime dtime ctime
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 7:
                    continue
                try:
                    key = hex(int(parts[0])) if parts[0].isdigit() else parts[0]
                    shmid = int(parts[1])
                    perms = parts[2]
                    size_bytes = int(parts[3])
                    cpid = int(parts[4]) if parts[4].isdigit() and int(parts[4]) > 0 else None
                    lpid = int(parts[5]) if parts[5].isdigit() and int(parts[5]) > 0 else None
                    nattch = int(parts[6])
                    owner = parts[7] if len(parts) > 7 else "unknown"

                    seg = ShmSegment(
                        id=shmid,
                        key=key,
                        owner=owner,
                        perms=perms,
                        bytes=size_bytes,
                        nattch=nattch,
                        cpid=cpid,
                        lpid=lpid,
                    )
                    cls._classify_shm_leak(seg)
                    segments.append(seg)
                except (ValueError, IndexError):
                    continue
        except Exception:
            pass
        return segments

    @classmethod
    def parse_ipcs_output(
        cls,
        text: str,
        pid_map: Optional[Dict[int, Tuple[Optional[int], Optional[int]]]] = None
    ) -> Tuple[List[ShmSegment], List[MessageQueue], List[SemaphoreSet]]:
        """Parses output of ipcs command (supporting both Linux and Darwin formats)."""
        pid_map = pid_map or {}
        lines = [line.strip() for line in text.splitlines()]

        # Determine if this is Darwin/BSD format or Linux format
        is_darwin = any("IPC status from <running system>" in line for line in lines) or \
                    any(line.startswith("T ") and "ID" in line for line in lines)

        if is_darwin:
            return cls._parse_darwin_ipcs(lines)
        else:
            return cls._parse_linux_ipcs(lines, pid_map)

    @classmethod
    def _parse_darwin_ipcs(
        cls, lines: List[str]
    ) -> Tuple[List[ShmSegment], List[MessageQueue], List[SemaphoreSet]]:
        """Parses Darwin/macOS/BSD style `ipcs -a` output."""
        shm_list: List[ShmSegment] = []
        msg_list: List[MessageQueue] = []
        sem_list: List[SemaphoreSet] = []

        current_section = None
        headers: List[str] = []

        for line in lines:
            if not line:
                continue

            # Detect section header
            if line.startswith("Message Queues:"):
                current_section = "msg"
                continue
            elif line.startswith("Shared Memory:"):
                current_section = "shm"
                continue
            elif line.startswith("Semaphores:"):
                current_section = "sem"
                continue

            # Detect header row: T     ID     KEY ...
            if line.startswith("T ") and "ID" in line and "KEY" in line:
                headers = line.split()
                continue

            parts = line.split()
            if not parts:
                continue

            # Check if this is a data row
            # Darwin format: first token is 'm', 'q', or 's', second token is ID
            token_type = parts[0]
            if token_type not in ("m", "q", "s") or len(parts) < 3:
                continue

            try:
                item_id = int(parts[1])
                key = parts[2]
                mode = parts[3] if len(parts) > 3 else ""
                owner = parts[4] if len(parts) > 4 else ""

                if token_type == "m" or current_section == "shm":
                    # Full headers: T ID KEY MODE OWNER GROUP CREATOR CGROUP NATTCH SEGSZ CPID LPID ATIME DTIME CTIME
                    nattch = 0
                    segsz = 0
                    cpid = None
                    lpid = None
                    atime = None
                    dtime = None
                    ctime = None

                    # If parsed with -a, NATTCH is index 8, SEGSZ index 9, CPID 10, LPID 11
                    if len(parts) >= 12:
                        try:
                            nattch = int(parts[8])
                            segsz = int(parts[9])
                            cpid = int(parts[10]) if parts[10].isdigit() else None
                            lpid = int(parts[11]) if parts[11].isdigit() else None
                            atime = parts[12] if len(parts) > 12 else None
                            dtime = parts[13] if len(parts) > 13 else None
                            ctime = parts[14] if len(parts) > 14 else None
                        except (ValueError, IndexError):
                            pass
                    elif len(parts) >= 8 and "SEGSZ" in headers:
                        # Try header-based matching
                        col_dict = dict(zip(headers, parts))
                        nattch = int(col_dict.get("NATTCH", 0))
                        segsz = int(col_dict.get("SEGSZ", 0))
                        cpid = int(col_dict.get("CPID", 0)) or None
                        lpid = int(col_dict.get("LPID", 0)) or None

                    seg = ShmSegment(
                        id=item_id,
                        key=key,
                        owner=owner,
                        perms=mode,
                        bytes=segsz,
                        nattch=nattch,
                        cpid=cpid,
                        lpid=lpid,
                        atime=atime,
                        dtime=dtime,
                        ctime=ctime,
                    )
                    cls._classify_shm_leak(seg)
                    shm_list.append(seg)

                elif token_type == "q" or current_section == "msg":
                    # Darwin msg headers: T ID KEY MODE OWNER GROUP CREATOR CGROUP CBYTES QNUM QBYTES LSPID LRPID STIME RTIME CTIME
                    cbytes = 0
                    qnum = 0
                    qbytes = None
                    lspid = None
                    lrpid = None
                    if len(parts) >= 12:
                        try:
                            cbytes = int(parts[8])
                            qnum = int(parts[9])
                            qbytes = int(parts[10])
                            lspid = int(parts[11]) if parts[11].isdigit() else None
                            lrpid = int(parts[12]) if len(parts) > 12 and parts[12].isdigit() else None
                        except (ValueError, IndexError):
                            pass

                    msg = MessageQueue(
                        id=item_id,
                        key=key,
                        owner=owner,
                        perms=mode,
                        used_bytes=cbytes,
                        messages=qnum,
                        qbytes=qbytes,
                        lspid=lspid,
                        lrpid=lrpid,
                    )
                    cls._classify_msg_leak(msg)
                    msg_list.append(msg)

                elif token_type == "s" or current_section == "sem":
                    # Darwin sem headers: T ID KEY MODE OWNER GROUP CREATOR CGROUP NSEMS OTIME CTIME
                    nsems = 1
                    if len(parts) >= 9:
                        try:
                            nsems = int(parts[8])
                        except (ValueError, IndexError):
                            pass

                    sem = SemaphoreSet(
                        id=item_id,
                        key=key,
                        owner=owner,
                        perms=mode,
                        nsems=nsems,
                    )
                    cls._classify_sem_leak(sem)
                    sem_list.append(sem)

            except (ValueError, IndexError):
                continue

        return shm_list, msg_list, sem_list

    @classmethod
    def _parse_linux_ipcs(
        cls,
        lines: List[str],
        pid_map: Dict[int, Tuple[Optional[int], Optional[int]]]
    ) -> Tuple[List[ShmSegment], List[MessageQueue], List[SemaphoreSet]]:
        """Parses standard Linux util-linux `ipcs` tabular output."""
        shm_list: List[ShmSegment] = []
        msg_list: List[MessageQueue] = []
        sem_list: List[SemaphoreSet] = []

        current_section = None
        headers: List[str] = []

        for line in lines:
            if not line:
                continue

            line_lower = line.lower()
            # Detect section transitions (must be enclosed in dashes or be section headers)
            if line.startswith("-") or line.endswith("-"):
                if "shared memory" in line_lower:
                    current_section = "shm"
                    headers = []
                    continue
                elif "message" in line_lower or "msg" in line_lower:
                    current_section = "msg"
                    headers = []
                    continue
                elif "semaphore" in line_lower or "sem" in line_lower:
                    current_section = "sem"
                    headers = []
                    continue

            # Check if this line is a header row
            parts = line.split()
            if not parts:
                continue

            if "key" in [p.lower() for p in parts] and any(
                id_word in [p.lower() for p in parts] for id_word in ["shmid", "msqid", "semid", "id"]
            ):
                headers = [p.lower() for p in parts]
                continue

            # If line is separator or doesn't start with key/hex/int, skip
            if line.startswith("-") or not headers:
                continue

            # Check if row starts with a key (hex like 0x... or integer)
            col_dict = dict(zip(headers, parts))
            # If parts has more items than headers (e.g. status column 'dest' at the end)
            if len(parts) > len(headers):
                trailing = " ".join(parts[len(headers) - 1:])
                last_header = headers[-1]
                col_dict[last_header] = trailing

            try:
                key = col_dict.get("key", parts[0])

                if current_section == "shm":
                    shmid_str = col_dict.get("shmid", col_dict.get("id"))
                    if not shmid_str or not shmid_str.isdigit():
                        continue
                    shmid = int(shmid_str)
                    owner = col_dict.get("owner", "unknown")
                    perms = col_dict.get("perms", "")
                    size_bytes = int(col_dict.get("bytes", col_dict.get("size", "0")))
                    nattch = int(col_dict.get("nattch", "0"))
                    status = col_dict.get("status", "")

                    cpid, lpid = pid_map.get(shmid, (None, None))
                    seg = ShmSegment(
                        id=shmid,
                        key=key,
                        owner=owner,
                        perms=perms,
                        bytes=size_bytes,
                        nattch=nattch,
                        status=status,
                        cpid=cpid,
                        lpid=lpid,
                    )
                    cls._classify_shm_leak(seg)
                    shm_list.append(seg)

                elif current_section == "msg":
                    msqid_str = col_dict.get("msqid", col_dict.get("id"))
                    if not msqid_str or not msqid_str.isdigit():
                        continue
                    msqid = int(msqid_str)
                    owner = col_dict.get("owner", "unknown")
                    perms = col_dict.get("perms", "")
                    used_bytes = int(col_dict.get("used-bytes", col_dict.get("bytes", "0")))
                    messages = int(col_dict.get("messages", col_dict.get("qnum", "0")))

                    msg = MessageQueue(
                        id=msqid,
                        key=key,
                        owner=owner,
                        perms=perms,
                        used_bytes=used_bytes,
                        messages=messages,
                    )
                    cls._classify_msg_leak(msg)
                    msg_list.append(msg)

                elif current_section == "sem":
                    semid_str = col_dict.get("semid", col_dict.get("id"))
                    if not semid_str or not semid_str.isdigit():
                        continue
                    semid = int(semid_str)
                    owner = col_dict.get("owner", "unknown")
                    perms = col_dict.get("perms", "")
                    nsems = int(col_dict.get("nsems", "1"))

                    sem = SemaphoreSet(
                        id=semid,
                        key=key,
                        owner=owner,
                        perms=perms,
                        nsems=nsems,
                    )
                    cls._classify_sem_leak(sem)
                    sem_list.append(sem)

            except (ValueError, IndexError):
                continue

        return shm_list, msg_list, sem_list

    @classmethod
    def _classify_shm_leak(cls, seg: ShmSegment) -> None:
        """Evaluates whether a shared memory segment is abandoned / leaked."""
        seg.creator_process = inspect_pid(seg.cpid)
        seg.last_process = inspect_pid(seg.lpid)

        # 1. Active attachments: not abandoned
        if seg.nattch > 0:
            seg.is_abandoned = False
            seg.leak_confidence = LeakConfidence.NONE
            return

        # 2. Zero attachments (nattch == 0)
        reasons = ["Zero active process attachments (nattch=0)"]

        # Check status flag
        if "dest" in seg.status.lower():
            reasons.append("Segment marked for destruction (status='dest') but still lingering in RAM")

        # Check process liveness
        cpid_dead = is_pid_dead(seg.cpid)
        lpid_dead = is_pid_dead(seg.lpid)

        if seg.cpid and cpid_dead:
            reasons.append(f"Creator process (PID {seg.cpid}) has exited/terminated")
        if seg.lpid and lpid_dead and seg.lpid != seg.cpid:
            reasons.append(f"Last operator process (PID {seg.lpid}) has exited/terminated")

        seg.is_abandoned = True
        seg.leak_reasons = reasons

        if "dest" in seg.status.lower() or cpid_dead or (seg.cpid is None and seg.nattch == 0):
            seg.leak_confidence = LeakConfidence.HIGH
        else:
            seg.leak_confidence = LeakConfidence.MEDIUM

    @classmethod
    def _classify_msg_leak(cls, msg: MessageQueue) -> None:
        """Evaluates whether a message queue is abandoned."""
        msg.creator_process = inspect_pid(msg.cpid)
        cpid_dead = is_pid_dead(msg.cpid)

        if cpid_dead and msg.messages == 0:
            msg.is_abandoned = True
            msg.leak_confidence = LeakConfidence.HIGH
            msg.leak_reasons = [
                "Empty message queue (0 messages)",
                f"Creator process (PID {msg.cpid or 'unknown'}) is terminated"
            ]
        elif msg.messages == 0:
            msg.is_abandoned = True
            msg.leak_confidence = LeakConfidence.MEDIUM
            msg.leak_reasons = ["Zero buffered messages and idle"]
        else:
            msg.is_abandoned = False
            msg.leak_confidence = LeakConfidence.NONE

    @classmethod
    def _classify_sem_leak(cls, sem: SemaphoreSet) -> None:
        """Evaluates whether a semaphore set is abandoned."""
        sem.creator_process = inspect_pid(sem.cpid)
        cpid_dead = is_pid_dead(sem.cpid)

        if sem.cpid and cpid_dead:
            sem.is_abandoned = True
            sem.leak_confidence = LeakConfidence.HIGH
            sem.leak_reasons = [f"Creator process (PID {sem.cpid}) is dead"]
        else:
            sem.is_abandoned = False
            sem.leak_confidence = LeakConfidence.NONE

    @classmethod
    def fetch_all(cls) -> Tuple[List[ShmSegment], List[MessageQueue], List[SemaphoreSet]]:
        """Main entry point to fetch and parse all current system IPC objects."""
        # On Linux, try /proc/sysvipc/shm if present
        if os.path.exists("/proc/sysvipc/shm"):
            shm_proc = cls.parse_proc_sysvipc_shm()
            # Still run ipcs for semaphores and message queues
            raw_ipcs = cls.run_ipcs("-a")
            pid_map = cls.run_ipcs_pids()
            _, msg_list, sem_list = cls.parse_ipcs_output(raw_ipcs, pid_map)
            return shm_proc, msg_list, sem_list

        # Otherwise parse from standard ipcs
        raw_ipcs = cls.run_ipcs("-a")
        pid_map = cls.run_ipcs_pids()
        return cls.parse_ipcs_output(raw_ipcs, pid_map)
