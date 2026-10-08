"""
Simulator tool for creating controlled IPC resource leaks.
Used for testing, evaluation, benchmarks, and instructor demonstrations.
"""

import json
import os
import subprocess
from typing import Any, Dict, List

from ipc_cleaner.core.syscalls import libc_create_msg, libc_create_sem, libc_create_shm
from ipc_cleaner.models import format_bytes_human


def simulate_ipc_leak(
    shm_count: int = 2,
    size_bytes: int = 1048576,
    sem_count: int = 0,
    msg_count: int = 0
) -> Dict[str, Any]:
    """
    Simulates abandoned IPC resource leaks for testing and verification.
    Allocates shared memory segments / semaphores / message queues, detaches,
    and terminates the creator process so attachments drop to 0 and the creator is dead.
    Args:
        shm_count: Number of shared memory segments to create (default 2)
        size_bytes: Size of each shared memory segment in bytes (default 1 MB)
        sem_count: Number of semaphore sets to create (default 0)
        msg_count: Number of message queues to create (default 0)
    Returns:
        Dictionary with created IDs, size, and simulator PID.
    """
    bin_path = os.path.join(os.path.dirname(__file__), "..", "..", "bin", "leak_generator")
    bin_path = os.path.abspath(bin_path)

    # 1. Prefer native C leak_generator binary if available
    if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
        try:
            cmd = [
                bin_path,
                "--shm", str(shm_count),
                "--size", str(size_bytes),
                "--sem", str(sem_count),
                "--msg", str(msg_count),
                "--json"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            data = json.loads(res.stdout.strip())
            total_ram = len(data.get("shm", [])) * size_bytes
            return {
                "status": "success",
                "method": "c_binary",
                "creator_pid": data.get("pid"),
                "created_shm_ids": data.get("shm", []),
                "created_sem_ids": data.get("sem", []),
                "created_msg_ids": data.get("msg", []),
                "bytes_per_shm": size_bytes,
                "total_leaked_ram_bytes": total_ram,
                "total_leaked_ram_human": format_bytes_human(total_ram),
                "message": (
                    f"Successfully simulated {len(data.get('shm', []))} abandoned SHM segments "
                    f"({format_bytes_human(total_ram)}) and {len(data.get('sem', []))} semaphores. "
                    f"Creator PID has exited, leaving nattch=0."
                )
            }
        except Exception:
            pass

    # 2. Python subprocess fallback via python -c
    script = f"""
import json, os, sys
from ipc_cleaner.core.syscalls import libc_create_shm, libc_create_sem, libc_create_msg

shm_ids = []
for _ in range({shm_count}):
    sid, _ = libc_create_shm({size_bytes})
    if sid is not None and sid >= 0:
        shm_ids.append(sid)

sem_ids = []
for _ in range({sem_count}):
    sid, _ = libc_create_sem()
    if sid is not None and sid >= 0:
        sem_ids.append(sid)

msg_ids = []
for _ in range({msg_count}):
    mid, _ = libc_create_msg()
    if mid is not None and mid >= 0:
        msg_ids.append(mid)

print(json.dumps({{'pid': os.getpid(), 'shm': shm_ids, 'sem': sem_ids, 'msg': msg_ids}}))
"""
    res = subprocess.run(
        ["python3", "-c", script],
        capture_output=True,
        text=True,
        check=True
    )
    data = json.loads(res.stdout.strip())
    total_ram = len(data.get("shm", [])) * size_bytes
    return {
        "status": "success",
        "method": "python_subprocess",
        "creator_pid": data.get("pid"),
        "created_shm_ids": data.get("shm", []),
        "created_sem_ids": data.get("sem", []),
        "created_msg_ids": data.get("msg", []),
        "bytes_per_shm": size_bytes,
        "total_leaked_ram_bytes": total_ram,
        "total_leaked_ram_human": format_bytes_human(total_ram),
        "message": (
            f"Successfully simulated {len(data.get('shm', []))} abandoned SHM segments "
            f"({format_bytes_human(total_ram)}) via subshell."
        )
    }
