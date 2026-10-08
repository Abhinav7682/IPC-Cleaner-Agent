"""
Cleaner tools for purging leaked and abandoned IPC resources.
Provides purge_shared_memory, purge_message_queues, purge_semaphores, and purge_abandoned_ipc.
"""

from typing import Any, Dict, List, Optional
from ipc_cleaner.core.executor import IPCExecutor
from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.models import LeakConfidence, format_bytes_human


def purge_shared_memory(
    shm_ids: List[int],
    dry_run: bool = False,
    force: bool = False
) -> Dict[str, Any]:
    """
    Purges specific System V Shared Memory segments by ID using ipcrm -m / shmctl.
    Args:
        shm_ids: List of integer shared memory segment IDs to delete.
        dry_run: If True, calculates reclaimed memory without making changes to OS.
        force: If True, allows deleting segments with active attachments (WARNING: dangerous).
    Returns:
        Structured result detailing purged IDs, failed IDs, and reclaimed RAM.
    """
    res = IPCExecutor.purge_shm_batch(shm_ids=shm_ids, dry_run=dry_run, force=force)
    return res.model_dump()


def purge_message_queues(
    msg_ids: List[int],
    dry_run: bool = False,
    force: bool = False
) -> Dict[str, Any]:
    """
    Purges specific System V Message Queues by ID using ipcrm -q / msgctl.
    Args:
        msg_ids: List of integer message queue IDs to delete.
        dry_run: If True, simulates deletion without changing system state.
        force: If True, allows deleting queues that still contain unread messages.
    Returns:
        Structured result detailing purged IDs, failed IDs, and reclaimed buffer bytes.
    """
    res = IPCExecutor.purge_msg_batch(msg_ids=msg_ids, dry_run=dry_run, force=force)
    return res.model_dump()


def purge_semaphores(
    sem_ids: List[int],
    dry_run: bool = False,
    force: bool = False
) -> Dict[str, Any]:
    """
    Purges specific System V Semaphore sets by ID using ipcrm -s / semctl.
    Args:
        sem_ids: List of integer semaphore set IDs to delete.
        dry_run: If True, simulates deletion without changing system state.
        force: If True, bypasses non-creator safety checks.
    Returns:
        Structured result detailing purged IDs and failed IDs.
    """
    res = IPCExecutor.purge_sem_batch(sem_ids=sem_ids, dry_run=dry_run, force=force)
    return res.model_dump()


def purge_abandoned_ipc(
    resource_type: str = "all",
    dry_run: bool = False,
    min_confidence: str = "MEDIUM",
    force: bool = False
) -> Dict[str, Any]:
    """
    Autonomously audits and purges abandoned System V IPC resources.
    Targets shared memory segments with zero attachments (nattch=0), dead creator processes,
    and orphan semaphores/queues.
    Args:
        resource_type: 'shm', 'msg', 'sem', or 'all'
        dry_run: If True, previews candidate resources and memory savings without removing them.
        min_confidence: 'HIGH' (dead creator or dest flag) or 'MEDIUM' (all nattch=0)
        force: If True, overrides active attachment checks (default False).
    Returns:
        Comprehensive cleanup report with reclaimed RAM and removed IDs.
    """
    all_shm, all_msg, all_sem = IPCParser.fetch_all()
    res_type = resource_type.lower()

    target_confidence = [LeakConfidence.HIGH]
    if min_confidence.upper() in ("MEDIUM", "LOW"):
        target_confidence.append(LeakConfidence.MEDIUM)
    if min_confidence.upper() == "LOW":
        target_confidence.append(LeakConfidence.LOW)

    shm_to_purge: List[int] = []
    if res_type in ("shm", "all"):
        for s in all_shm:
            if s.is_abandoned and s.nattch == 0 and s.leak_confidence in target_confidence:
                shm_to_purge.append(s.id)

    msg_to_purge: List[int] = []
    if res_type in ("msg", "all"):
        for m in all_msg:
            if m.is_abandoned and m.leak_confidence in target_confidence:
                msg_to_purge.append(m.id)

    sem_to_purge: List[int] = []
    if res_type in ("sem", "all"):
        for sem in all_sem:
            if sem.is_abandoned and sem.leak_confidence in target_confidence:
                sem_to_purge.append(sem.id)

    # Perform purges
    shm_result = IPCExecutor.purge_shm_batch(shm_to_purge, dry_run=dry_run, force=force) if shm_to_purge else None
    msg_result = IPCExecutor.purge_msg_batch(msg_to_purge, dry_run=dry_run, force=force) if msg_to_purge else None
    sem_result = IPCExecutor.purge_sem_batch(sem_to_purge, dry_run=dry_run, force=force) if sem_to_purge else None

    total_reclaimed = (shm_result.reclaimed_bytes if shm_result else 0) + \
                      (msg_result.reclaimed_bytes if msg_result else 0)

    return {
        "status": "success",
        "dry_run": dry_run,
        "resource_type_filter": resource_type,
        "min_confidence_filter": min_confidence,
        "reclaimed_ram_bytes": total_reclaimed,
        "reclaimed_ram_human": format_bytes_human(total_reclaimed),
        "shared_memory": shm_result.model_dump() if shm_result else {
            "requested_ids": [], "purged_ids": [], "failed_ids": {}, "reclaimed_bytes": 0
        },
        "message_queues": msg_result.model_dump() if msg_result else {
            "requested_ids": [], "purged_ids": [], "failed_ids": {}, "reclaimed_bytes": 0
        },
        "semaphores": sem_result.model_dump() if sem_result else {
            "requested_ids": [], "purged_ids": [], "failed_ids": {}, "reclaimed_bytes": 0
        }
    }
