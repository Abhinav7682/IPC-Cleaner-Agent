"""
Tools package for IPC Cleaner Agent.
Exposes Linux IPC capabilities as callable functions with schemas for LLM Function Calling.
"""

from ipc_cleaner.tools.audit import (
    audit_ipc_leaks,
    get_ipc_summary,
    inspect_ipc_resource,
    list_ipc_resources,
)
from ipc_cleaner.tools.cleaner import (
    purge_abandoned_ipc,
    purge_message_queues,
    purge_semaphores,
    purge_shared_memory,
)
from ipc_cleaner.tools.simulator import simulate_ipc_leak

__all__ = [
    "list_ipc_resources",
    "audit_ipc_leaks",
    "get_ipc_summary",
    "inspect_ipc_resource",
    "purge_shared_memory",
    "purge_message_queues",
    "purge_semaphores",
    "purge_abandoned_ipc",
    "simulate_ipc_leak",
]
