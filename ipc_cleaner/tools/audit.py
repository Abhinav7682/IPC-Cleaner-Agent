"""
Audit tools for inspecting and identifying leaked IPC resources.
Provides list_ipc_resources, audit_ipc_leaks, get_ipc_summary, and inspect_ipc_resource.
"""

from datetime import datetime
import subprocess
from typing import Any, Dict, List, Optional

from ipc_cleaner.core.parser import IPCParser
from ipc_cleaner.models import (
    AuditReport,
    LeakConfidence,
    MessageQueue,
    ResourceType,
    SemaphoreSet,
    ShmSegment,
    format_bytes_human,
)


def list_ipc_resources(resource_type: str = "all") -> Dict[str, Any]:
    """
    Lists active System V IPC resources on the system.
    Args:
        resource_type: 'shm' (shared memory), 'msg' (message queues), 'sem' (semaphores), or 'all'.
    Returns:
        Structured dictionary listing resources, attachment counts, and memory usage.
    """
    all_shm, all_msg, all_sem = IPCParser.fetch_all()
    res_type = resource_type.lower()

    result: Dict[str, Any] = {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "filter": resource_type,
    }

    if res_type in ("shm", "all"):
        result["shared_memory"] = [s.model_dump() for s in all_shm]
        result["total_shm_bytes"] = sum(s.bytes for s in all_shm)
        result["total_shm_human"] = format_bytes_human(result["total_shm_bytes"])

    if res_type in ("msg", "all"):
        result["message_queues"] = [m.model_dump() for m in all_msg]
        result["total_msg_count"] = len(all_msg)

    if res_type in ("sem", "all"):
        result["semaphores"] = [s.model_dump() for s in all_sem]
        result["total_sem_count"] = len(all_sem)

    return result


def audit_ipc_leaks(
    resource_type: str = "all",
    min_confidence: str = "MEDIUM",
    only_zero_attachments: bool = True
) -> Dict[str, Any]:
    """
    Audits the operating system for abandoned IPC resources and memory leaks.
    Identifies shared memory segments with 0 attachments and dead creator processes.
    Args:
        resource_type: 'shm', 'msg', 'sem', or 'all'
        min_confidence: 'HIGH' (dead creator / dest flag) or 'MEDIUM' (nattch=0)
        only_zero_attachments: Require nattch == 0 for shared memory
    Returns:
        Audit report containing leaked segments, reclaimable RAM, and leak reasons.
    """
    all_shm, all_msg, all_sem = IPCParser.fetch_all()
    res_type = resource_type.lower()

    conf_threshold = [LeakConfidence.HIGH]
    if min_confidence.upper() in ("MEDIUM", "LOW"):
        conf_threshold.append(LeakConfidence.MEDIUM)
    if min_confidence.upper() == "LOW":
        conf_threshold.append(LeakConfidence.LOW)

    leaked_shm: List[ShmSegment] = []
    if res_type in ("shm", "all"):
        for s in all_shm:
            if not s.is_abandoned:
                continue
            if only_zero_attachments and s.nattch != 0:
                continue
            if s.leak_confidence in conf_threshold:
                leaked_shm.append(s)

    leaked_msg: List[MessageQueue] = []
    if res_type in ("msg", "all"):
        for m in all_msg:
            if m.is_abandoned and m.leak_confidence in conf_threshold:
                leaked_msg.append(m)

    leaked_sem: List[SemaphoreSet] = []
    if res_type in ("sem", "all"):
        for sem in all_sem:
            if sem.is_abandoned and sem.leak_confidence in conf_threshold:
                leaked_sem.append(sem)

    reclaimable_ram = sum(s.bytes for s in leaked_shm)

    report = AuditReport(
        timestamp=datetime.now().isoformat(),
        total_shm_count=len(all_shm),
        total_shm_bytes=sum(s.bytes for s in all_shm),
        total_msg_count=len(all_msg),
        total_sem_count=len(all_sem),
        abandoned_shm_count=len(leaked_shm),
        abandoned_shm_bytes=reclaimable_ram,
        abandoned_msg_count=len(leaked_msg),
        abandoned_sem_count=len(leaked_sem),
        abandoned_shm=leaked_shm,
        abandoned_msg=leaked_msg,
        abandoned_sem=leaked_sem,
        reclaimable_ram_bytes=reclaimable_ram,
        reclaimable_ram_human=format_bytes_human(reclaimable_ram),
        all_shm=all_shm,
        all_msg=all_msg,
        all_sem=all_sem
    )

    return report.model_dump()


def get_ipc_summary() -> Dict[str, Any]:
    """
    Returns high-level summary of IPC subsystem, allocated RAM, and active objects.
    """
    all_shm, all_msg, all_sem = IPCParser.fetch_all()
    abandoned_shm = [s for s in all_shm if s.is_abandoned]
    total_ram = sum(s.bytes for s in all_shm)
    leaked_ram = sum(s.bytes for s in abandoned_shm)

    limits_info = {}
    try:
        res = subprocess.run(["ipcs", "-l"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            limits_info["raw_limits"] = res.stdout
    except Exception:
        pass

    return {
        "status": "success",
        "timestamp": datetime.now().isoformat(),
        "shared_memory": {
            "total_segments": len(all_shm),
            "total_ram_bytes": total_ram,
            "total_ram_human": format_bytes_human(total_ram),
            "abandoned_segments": len(abandoned_shm),
            "leaked_ram_bytes": leaked_ram,
            "leaked_ram_human": format_bytes_human(leaked_ram),
        },
        "message_queues": {
            "total_queues": len(all_msg),
            "abandoned_queues": len([m for m in all_msg if m.is_abandoned]),
        },
        "semaphores": {
            "total_sets": len(all_sem),
            "abandoned_sets": len([s for s in all_sem if s.is_abandoned]),
        },
        "system_limits": limits_info
    }


def inspect_ipc_resource(resource_type: str, resource_id: int) -> Dict[str, Any]:
    """
    Inspects a single IPC resource in deep detail.
    Args:
        resource_type: 'shm', 'msg', or 'sem'
        resource_id: The integer ID of the resource
    """
    res_type = resource_type.lower()
    all_shm, all_msg, all_sem = IPCParser.fetch_all()

    if res_type == "shm":
        matches = [s for s in all_shm if s.id == resource_id]
        if not matches:
            return {"status": "error", "message": f"Shared memory segment ID {resource_id} not found."}
        return {"status": "success", "resource_type": "shm", "details": matches[0].model_dump()}

    elif res_type == "msg":
        matches = [m for m in all_msg if m.id == resource_id]
        if not matches:
            return {"status": "error", "message": f"Message queue ID {resource_id} not found."}
        return {"status": "success", "resource_type": "msg", "details": matches[0].model_dump()}

    elif res_type == "sem":
        matches = [s for s in all_sem if s.id == resource_id]
        if not matches:
            return {"status": "error", "message": f"Semaphore set ID {resource_id} not found."}
        return {"status": "success", "resource_type": "sem", "details": matches[0].model_dump()}

    return {"status": "error", "message": f"Unknown resource type: {resource_type}"}
