"""
Direct libc System Call interface for System V IPC operations using ctypes.
Executes raw shmctl, semctl, msgctl, shmget, semget, msgget system calls.
"""

import ctypes
import ctypes.util
import os
from typing import Optional, Tuple

# Load system C standard library
_libc_path = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_path, use_errno=True) if _libc_path else None

# System V IPC Constants
IPC_PRIVATE = 0
IPC_RMID = 0
IPC_SET = 1
IPC_STAT = 2
IPC_CREAT = 0o1000
IPC_EXCL = 0o2000

# Function prototypes
if _libc:
    # int shmget(key_t key, size_t size, int shmflg);
    if hasattr(_libc, "shmget"):
        _libc.shmget.argtypes = [ctypes.c_int, ctypes.c_size_t, ctypes.c_int]
        _libc.shmget.restype = ctypes.c_int

    # int shmctl(int shmid, int cmd, struct shmid_ds *buf);
    if hasattr(_libc, "shmctl"):
        _libc.shmctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        _libc.shmctl.restype = ctypes.c_int

    # int semget(key_t key, int nsems, int semflg);
    if hasattr(_libc, "semget"):
        _libc.semget.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_int]
        _libc.semget.restype = ctypes.c_int

    # int semctl(int semid, int semnum, int cmd, ...);
    if hasattr(_libc, "semctl"):
        _libc.semctl.restype = ctypes.c_int

    # int msgget(key_t key, int msgflg);
    if hasattr(_libc, "msgget"):
        _libc.msgget.argtypes = [ctypes.c_int, ctypes.c_int]
        _libc.msgget.restype = ctypes.c_int

    # int msgctl(int msqid, int cmd, struct msqid_ds *buf);
    if hasattr(_libc, "msgctl"):
        _libc.msgctl.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
        _libc.msgctl.restype = ctypes.c_int


def libc_shmctl_rmid(shmid: int) -> Tuple[bool, Optional[str]]:
    """Directly invokes shmctl(shmid, IPC_RMID, NULL) system call to mark/remove shared memory."""
    if not _libc or not hasattr(_libc, "shmctl"):
        return False, "libc shmctl symbol not available"

    res = _libc.shmctl(ctypes.c_int(shmid), ctypes.c_int(IPC_RMID), None)
    if res == 0:
        return True, None
    errno = ctypes.get_errno()
    return False, f"shmctl error {errno}: {os.strerror(errno)}"


def libc_semctl_rmid(semid: int) -> Tuple[bool, Optional[str]]:
    """Directly invokes semctl(semid, 0, IPC_RMID) system call to remove semaphore set."""
    if not _libc or not hasattr(_libc, "semctl"):
        return False, "libc semctl symbol not available"

    res = _libc.semctl(ctypes.c_int(semid), ctypes.c_int(0), ctypes.c_int(IPC_RMID))
    if res == 0:
        return True, None
    errno = ctypes.get_errno()
    return False, f"semctl error {errno}: {os.strerror(errno)}"


def libc_semctl_get_stats(semid: int, semnum: int = 0) -> Tuple[Optional[int], int, int]:
    """
    Directly queries semaphore statistics via semctl:
    GETPID (11): PID of last process to perform semop
    GETNCNT (14): Number of processes waiting for semval to become greater than current value
    GETZCNT (15): Number of processes waiting for semval to become 0
    Returns: (last_pid, ncount, zcount)
    """
    if not _libc or not hasattr(_libc, "semctl"):
        return None, 0, 0

    try:
        GETPID = 11
        GETNCNT = 14
        GETZCNT = 15
        last_pid = _libc.semctl(ctypes.c_int(semid), ctypes.c_int(semnum), ctypes.c_int(GETPID))
        ncnt = _libc.semctl(ctypes.c_int(semid), ctypes.c_int(semnum), ctypes.c_int(GETNCNT))
        zcnt = _libc.semctl(ctypes.c_int(semid), ctypes.c_int(semnum), ctypes.c_int(GETZCNT))
        valid_pid = int(last_pid) if last_pid > 0 else None
        return valid_pid, max(0, int(ncnt)), max(0, int(zcnt))
    except Exception:
        return None, 0, 0


def libc_msgctl_rmid(msqid: int) -> Tuple[bool, Optional[str]]:
    """Directly invokes msgctl(msqid, IPC_RMID, NULL) system call to remove message queue."""
    if not _libc or not hasattr(_libc, "msgctl"):
        return False, "libc msgctl symbol not available"

    res = _libc.msgctl(ctypes.c_int(msqid), ctypes.c_int(IPC_RMID), None)
    if res == 0:
        return True, None
    errno = ctypes.get_errno()
    return False, f"msgctl error {errno}: {os.strerror(errno)}"


def libc_create_shm(size_bytes: int = 1048576, mode: int = 0o600) -> Tuple[Optional[int], Optional[str]]:
    """Creates a temporary shared memory segment via shmget."""
    if not _libc or not hasattr(_libc, "shmget"):
        return None, "libc shmget symbol not available"

    flags = mode | IPC_CREAT
    shmid = _libc.shmget(ctypes.c_int(IPC_PRIVATE), ctypes.c_size_t(size_bytes), ctypes.c_int(flags))
    if shmid >= 0:
        return shmid, None
    errno = ctypes.get_errno()
    return None, f"shmget error {errno}: {os.strerror(errno)}"


def libc_create_sem(nsems: int = 1, mode: int = 0o600) -> Tuple[Optional[int], Optional[str]]:
    """Creates a temporary semaphore set via semget."""
    if not _libc or not hasattr(_libc, "semget"):
        return None, "libc semget symbol not available"

    flags = mode | IPC_CREAT
    semid = _libc.semget(ctypes.c_int(IPC_PRIVATE), ctypes.c_int(nsems), ctypes.c_int(flags))
    if semid >= 0:
        return semid, None
    errno = ctypes.get_errno()
    return None, f"semget error {errno}: {os.strerror(errno)}"


def libc_create_msg(mode: int = 0o600) -> Tuple[Optional[int], Optional[str]]:
    """Creates a temporary message queue via msgget."""
    if not _libc or not hasattr(_libc, "msgget"):
        return None, "libc msgget symbol not available"

    flags = mode | IPC_CREAT
    msqid = _libc.msgget(ctypes.c_int(IPC_PRIVATE), ctypes.c_int(flags))
    if msqid >= 0:
        return msqid, None
    errno = ctypes.get_errno()
    return None, f"msgget error {errno}: {os.strerror(errno)}"
