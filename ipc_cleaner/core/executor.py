"""
Safe execution layer for IPC resource purging.
Supports dry-run verification, attachment safety checks, subprocess ipcrm execution,
and direct libc syscall fallbacks.
"""

import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.core.syscalls import libc_msgctl_rmid, libc_semctl_rmid, libc_shmctl_rmid
from ipc_cleaner.models import PurgeResult, format_bytes_human


class IPCExecutor:
    """Executes ipcrm commands or libc syscalls with safety validations."""

    @staticmethod
    def _has_ipcrm() -> bool:
        return shutil.which("ipcrm") is not None

    @classmethod
    def remove_shm_single(
        cls,
        shmid: int,
        force: bool = False,
        dry_run: bool = False,
        cached_segments: Optional[Dict[int, Any]] = None
    ) -> Tuple[bool, int, Optional[str]]:
        """
        Removes a single shared memory segment.
        Returns: (success, bytes_reclaimed, error_message)
        """
        # Safety check: fetch current status
        seg = None
        if cached_segments and shmid in cached_segments:
            seg = cached_segments[shmid]
        else:
            all_shm, _, _ = IPCParser.fetch_all()
            matching = [s for s in all_shm if s.id == shmid]
            if matching:
                seg = matching[0]

        if not seg:
            return False, 0, f"Shared memory segment ID {shmid} not found on system."

        size_bytes = seg.bytes if hasattr(seg, "bytes") else int(seg)
        nattch = seg.nattch if hasattr(seg, "nattch") else 0

        if nattch > 0 and not force:
            return (
                False,
                0,
                f"Refusing to purge shmid {shmid}: active attachments detected (nattch={nattch}). "
                f"Use force=True to override safety lock."
            )

        if dry_run:
            return True, size_bytes, None

        # 1. Try ipcrm -m <shmid>
        if cls._has_ipcrm():
            try:
                res = subprocess.run(
                    ["ipcrm", "-m", str(shmid)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if res.returncode == 0:
                    return True, size_bytes, None
                err_text = (res.stderr or res.stdout).strip()
            except Exception as e:
                err_text = str(e)
        else:
            err_text = "ipcrm command not found"

        # 2. Fallback to direct libc syscall shmctl(IPC_RMID)
        success, libc_err = libc_shmctl_rmid(shmid)
        if success:
            return True, size_bytes, None

        combined_err = f"ipcrm failed ({err_text}); libc syscall fallback failed ({libc_err})"
        return False, 0, combined_err

    @classmethod
    def remove_msg_single(
        cls,
        msqid: int,
        force: bool = False,
        dry_run: bool = False,
        cached_queues: Optional[Dict[int, int]] = None,
        msg_info: Optional[Any] = None
    ) -> Tuple[bool, int, Optional[str]]:
        """Removes a single message queue. Returns: (success, used_bytes, error_message)."""
        used_bytes = 0
        queue = msg_info
        if queue:
            used_bytes = getattr(queue, "used_bytes", 0)
            if getattr(queue, "messages", 0) > 0 and not force:
                return (
                    False,
                    0,
                    f"Refusing to purge msqid {msqid}: contains {queue.messages} unread messages. "
                    f"Use force=True to override."
                )
        elif cached_queues and msqid in cached_queues:
            used_bytes = cached_queues[msqid]
        else:
            _, all_msg, _ = IPCParser.fetch_all()
            matching = [m for m in all_msg if m.id == msqid]
            if not matching:
                return False, 0, f"Message queue ID {msqid} not found on system."
            queue = matching[0]
            used_bytes = queue.used_bytes
            if queue.messages > 0 and not force:
                return (
                    False,
                    0,
                    f"Refusing to purge msqid {msqid}: contains {queue.messages} unread messages. "
                    f"Use force=True to override."
                )

        if dry_run:
            return True, used_bytes, None

        if cls._has_ipcrm():
            try:
                res = subprocess.run(
                    ["ipcrm", "-q", str(msqid)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if res.returncode == 0:
                    return True, used_bytes, None
                err_text = (res.stderr or res.stdout).strip()
            except Exception as e:
                err_text = str(e)
        else:
            err_text = "ipcrm command not found"

        success, libc_err = libc_msgctl_rmid(msqid)
        if success:
            return True, used_bytes, None

        return False, 0, f"ipcrm failed ({err_text}); libc syscall failed ({libc_err})"

    @classmethod
    def remove_sem_single(
        cls,
        semid: int,
        force: bool = False,
        dry_run: bool = False,
        cached_sems: Optional[Dict[int, Any]] = None,
        sem_info: Optional[Any] = None
    ) -> Tuple[bool, Optional[str]]:
        """Removes a single semaphore set. Returns: (success, error_message)."""
        sem = sem_info
        if not sem:
            if cached_sems and semid in cached_sems:
                sem = cached_sems[semid]
            else:
                _, _, all_sem = IPCParser.fetch_all()
                matching = [s for s in all_sem if s.id == semid]
                if matching:
                    sem = matching[0]

        if sem and getattr(sem, "nwaiters", 0) > 0 and not force:
            return (
                False,
                f"Refusing to purge semid {semid}: active waiting processes detected (nwaiters={sem.nwaiters}). "
                f"Use force=True to override safety lock."
            )

        if dry_run:
            return True, None

        if cls._has_ipcrm():
            try:
                res = subprocess.run(
                    ["ipcrm", "-s", str(semid)],
                    capture_output=True,
                    text=True,
                    check=False
                )
                if res.returncode == 0:
                    return True, None
                err_text = (res.stderr or res.stdout).strip()
            except Exception as e:
                err_text = str(e)
        else:
            err_text = "ipcrm command not found"

        success, libc_err = libc_semctl_rmid(semid)
        if success:
            return True, None

        return False, f"ipcrm failed ({err_text}); libc syscall failed ({libc_err})"

    @classmethod
    def purge_shm_batch(
        cls,
        shm_ids: List[int],
        dry_run: bool = False,
        force: bool = False
    ) -> PurgeResult:
        """Batch purges specified shared memory segment IDs."""
        all_shm, _, _ = IPCParser.fetch_all()
        shm_map = {s.id: s for s in all_shm}

        purged: List[int] = []
        failed: Dict[int, str] = {}
        total_bytes = 0

        # Filter and sanitize valid integer IDs
        clean_ids: List[int] = []
        for sid in shm_ids:
            if sid is None:
                continue
            try:
                clean_ids.append(int(sid))
            except (ValueError, TypeError):
                continue

        for sid in clean_ids:
            ok, b, err = cls.remove_shm_single(
                sid,
                force=force,
                dry_run=dry_run,
                cached_segments=shm_map
            )
            if ok:
                purged.append(sid)
                total_bytes += b
            else:
                failed[sid] = err or "Unknown error"

        return PurgeResult(
            resource_type="shm",
            requested_ids=clean_ids,
            purged_ids=purged,
            failed_ids=failed,
            reclaimed_bytes=total_bytes,
            reclaimed_bytes_human=format_bytes_human(total_bytes),
            dry_run=dry_run,
            method_used="ipcrm / shmctl"
        )

    @classmethod
    def purge_msg_batch(
        cls,
        msg_ids: List[int],
        dry_run: bool = False,
        force: bool = False
    ) -> PurgeResult:
        """Batch purges specified message queue IDs."""
        _, all_msg, _ = IPCParser.fetch_all()
        msg_map = {m.id: m.used_bytes for m in all_msg}

        purged: List[int] = []
        failed: Dict[int, str] = {}
        total_bytes = 0

        clean_ids: List[int] = []
        for mid in msg_ids:
            if mid is None:
                continue
            try:
                clean_ids.append(int(mid))
            except (ValueError, TypeError):
                continue

        for mid in clean_ids:
            ok, b, err = cls.remove_msg_single(
                mid,
                force=force,
                dry_run=dry_run,
                cached_queues=msg_map
            )
            if ok:
                purged.append(mid)
                total_bytes += b
            else:
                failed[mid] = err or "Unknown error"

        return PurgeResult(
            resource_type="msg",
            requested_ids=clean_ids,
            purged_ids=purged,
            failed_ids=failed,
            reclaimed_bytes=total_bytes,
            reclaimed_bytes_human=format_bytes_human(total_bytes),
            dry_run=dry_run,
            method_used="ipcrm / msgctl"
        )

    @classmethod
    def purge_sem_batch(
        cls,
        sem_ids: List[int],
        dry_run: bool = False,
        force: bool = False
    ) -> PurgeResult:
        """Batch purges specified semaphore set IDs."""
        _, _, all_sem = IPCParser.fetch_all()
        sem_map = {s.id: s for s in all_sem}

        purged: List[int] = []
        failed: Dict[int, str] = {}

        clean_ids: List[int] = []
        for sid in sem_ids:
            if sid is None:
                continue
            try:
                clean_ids.append(int(sid))
            except (ValueError, TypeError):
                continue

        for sid in clean_ids:
            ok, err = cls.remove_sem_single(sid, force=force, dry_run=dry_run, cached_sems=sem_map)
            if ok:
                purged.append(sid)
            else:
                failed[sid] = err or "Unknown error"

        return PurgeResult(
            resource_type="sem",
            requested_ids=clean_ids,
            purged_ids=purged,
            failed_ids=failed,
            reclaimed_bytes=0,
            reclaimed_bytes_human="0 B (Kernel handles)",
            dry_run=dry_run,
            method_used="ipcrm / semctl"
        )

