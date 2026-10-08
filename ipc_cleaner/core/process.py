"""
Process liveness and metadata resolver for IPC Creator/Operator PIDs.
Determines whether creator or last-operator processes are alive, dead, or zombies.
"""

import os
import subprocess
from typing import Optional
from ipc_cleaner.models import ProcessInfo

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


def inspect_pid(pid: Optional[int]) -> Optional[ProcessInfo]:
    """Inspects a PID to determine if it is alive, a zombie, or dead."""
    if pid is None or pid <= 0:
        return None

    # 1. Direct Linux procfs inspection if available
    proc_path = f"/proc/{pid}"
    if os.path.isdir(proc_path):
        is_zombie = False
        name = None
        cmdline = None
        username = None

        try:
            status_file = os.path.join(proc_path, "status")
            if os.path.exists(status_file):
                with open(status_file, "r") as f:
                    for line in f:
                        if line.startswith("State:"):
                            is_zombie = "Z" in line
                        elif line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
        except (IOError, PermissionError):
            pass

        try:
            cmd_file = os.path.join(proc_path, "cmdline")
            if os.path.exists(cmd_file):
                with open(cmd_file, "r", errors="ignore") as f:
                    cmdline = f.read().replace("\x00", " ").strip()
        except (IOError, PermissionError):
            pass

        return ProcessInfo(
            pid=pid,
            exists=True,
            is_zombie=is_zombie,
            name=name,
            cmdline=cmdline or name,
            username=username
        )

    # 2. psutil lookup if available
    if HAS_PSUTIL:
        try:
            proc = psutil.Process(pid)
            if proc.is_running():
                status = proc.status()
                is_zombie = (status == psutil.STATUS_ZOMBIE)
                try:
                    name = proc.name()
                except Exception:
                    name = None
                try:
                    cmdline = " ".join(proc.cmdline())
                except Exception:
                    cmdline = name
                try:
                    username = proc.username()
                except Exception:
                    username = None

                return ProcessInfo(
                    pid=pid,
                    exists=True,
                    is_zombie=is_zombie,
                    name=name,
                    cmdline=cmdline,
                    username=username
                )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return ProcessInfo(pid=pid, exists=False, is_zombie=True)
        except (psutil.AccessDenied, Exception):
            # Process exists but permission denied to query details
            return ProcessInfo(pid=pid, exists=True, is_zombie=False)

    # 3. System call fallback: os.kill(pid, 0)
    try:
        os.kill(pid, 0)
        # Process exists
        name = None
        try:
            res = subprocess.run(
                ["ps", "-p", str(pid), "-o", "comm="],
                capture_output=True,
                text=True,
                timeout=1
            )
            if res.returncode == 0 and res.stdout.strip():
                name = res.stdout.strip()
        except Exception:
            pass

        return ProcessInfo(pid=pid, exists=True, is_zombie=False, name=name)
    except PermissionError:
        # Process exists but belongs to another user
        return ProcessInfo(pid=pid, exists=True, is_zombie=False)
    except ProcessLookupError:
        # Process is dead / does not exist
        return ProcessInfo(pid=pid, exists=False, is_zombie=False)
    except Exception:
        return ProcessInfo(pid=pid, exists=False, is_zombie=False)


def is_pid_dead(pid: Optional[int]) -> bool:
    """Returns True if PID is dead or is a defunct zombie."""
    if pid is None or pid <= 0:
        return True
    info = inspect_pid(pid)
    if not info or not info.exists or info.is_zombie:
        return True
    return False
