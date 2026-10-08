"""
Function Calling JSON Schemas for IPC Cleaner Agent Tools.
Fully compatible with Gemini FunctionDeclaration, OpenAI tool definitions, and Anthropic tool specs.
"""

from typing import Any, Dict, List

TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "list_ipc_resources",
        "description": "Lists active System V IPC resources (shared memory segments, message queues, semaphores) with attachment counts, size, and owners.",
        "parameters": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["all", "shm", "msg", "sem"],
                    "description": "Type of IPC resource to list. Defaults to 'all'."
                }
            },
            "required": []
        }
    },
    {
        "name": "audit_ipc_leaks",
        "description": "Audits the OS for abandoned or leaked IPC resources (e.g. shared memory segments with 0 attachments whose creator process has died). Returns reclaimable RAM and leak diagnosis.",
        "parameters": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["all", "shm", "msg", "sem"],
                    "description": "Resource type to audit. Defaults to 'all'."
                },
                "min_confidence": {
                    "type": "string",
                    "enum": ["HIGH", "MEDIUM", "LOW"],
                    "description": "Confidence threshold. 'HIGH' requires dead creator PID or 'dest' flag; 'MEDIUM' includes any nattch=0 segment. Defaults to 'MEDIUM'."
                },
                "only_zero_attachments": {
                    "type": "boolean",
                    "description": "If true, strictly ignores any segment with active attachments (nattch > 0). Defaults to true."
                }
            },
            "required": []
        }
    },
    {
        "name": "get_ipc_summary",
        "description": "Returns high-level statistics of IPC usage, total RAM allocated to shared memory, count of leaked segments, and kernel IPC limits.",
        "parameters": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "inspect_ipc_resource",
        "description": "Inspects a specific IPC resource in deep detail given its type and identifier.",
        "parameters": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["shm", "msg", "sem"],
                    "description": "Type of resource: 'shm' for shared memory, 'msg' for message queue, 'sem' for semaphore."
                },
                "resource_id": {
                    "type": "integer",
                    "description": "The unique numerical ID (shmid, msqid, or semid) to inspect."
                }
            },
            "required": ["resource_type", "resource_id"]
        }
    },
    {
        "name": "purge_shared_memory",
        "description": "Purges specified shared memory segment IDs from the system using ipcrm -m / shmctl system calls. Verifies zero attachments before removal for safety.",
        "parameters": {
            "type": "object",
            "properties": {
                "shm_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of shared memory segment IDs (shmid) to remove."
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, simulates removal and calculates reclaimed RAM without altering the OS. Defaults to false."
                },
                "force": {
                    "type": "boolean",
                    "description": "If true, forces deletion even if attachments > 0 (dangerous). Defaults to false."
                }
            },
            "required": ["shm_ids"]
        }
    },
    {
        "name": "purge_message_queues",
        "description": "Purges specified message queues from the system using ipcrm -q / msgctl system calls.",
        "parameters": {
            "type": "object",
            "properties": {
                "msg_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of message queue IDs (msqid) to remove."
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, simulates removal without deleting. Defaults to false."
                },
                "force": {
                    "type": "boolean",
                    "description": "If true, forces deletion even if unread messages remain. Defaults to false."
                }
            },
            "required": ["msg_ids"]
        }
    },
    {
        "name": "purge_semaphores",
        "description": "Purges specified semaphore sets from the system using ipcrm -s / semctl system calls.",
        "parameters": {
            "type": "object",
            "properties": {
                "sem_ids": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "List of semaphore set IDs (semid) to remove."
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, simulates removal without deleting. Defaults to false."
                },
                "force": {
                    "type": "boolean",
                    "description": "If true, overrides creator checks. Defaults to false."
                }
            },
            "required": ["sem_ids"]
        }
    },
    {
        "name": "purge_abandoned_ipc",
        "description": "Autonomously audits and purges abandoned System V IPC resources (shared memory with 0 attachments, dead creator PIDs, and idle queues/semaphores) to reclaim RAM.",
        "parameters": {
            "type": "object",
            "properties": {
                "resource_type": {
                    "type": "string",
                    "enum": ["all", "shm", "msg", "sem"],
                    "description": "Type of abandoned resources to purge. Defaults to 'all'."
                },
                "dry_run": {
                    "type": "boolean",
                    "description": "If true, previews what would be cleaned and reclaimed RAM without removing anything. Defaults to false."
                },
                "min_confidence": {
                    "type": "string",
                    "enum": ["HIGH", "MEDIUM", "LOW"],
                    "description": "Confidence filter. 'HIGH' targets confirmed dead creator PIDs / dest flags. 'MEDIUM' includes all nattch=0 segments. Defaults to 'MEDIUM'."
                },
                "force": {
                    "type": "boolean",
                    "description": "If true, overrides attachment safety protections. Defaults to false."
                }
            },
            "required": []
        }
    },
    {
        "name": "simulate_ipc_leak",
        "description": "Creates controlled orphaned IPC resources (shared memory segments, semaphores) with nattch=0 and terminated creator PIDs for testing or benchmark purposes.",
        "parameters": {
            "type": "object",
            "properties": {
                "shm_count": {
                    "type": "integer",
                    "description": "Number of shared memory segments to create (default 2)."
                },
                "size_bytes": {
                    "type": "integer",
                    "description": "Size in bytes for each shared memory segment (default 1048576, i.e., 1MB)."
                },
                "sem_count": {
                    "type": "integer",
                    "description": "Number of semaphore sets to create (default 0)."
                },
                "msg_count": {
                    "type": "integer",
                    "description": "Number of message queues to create (default 0)."
                }
            },
            "required": []
        }
    }
]


def get_openai_tools() -> List[Dict[str, Any]]:
    """Converts schema to OpenAI tool call format."""
    return [{"type": "function", "function": schema} for schema in TOOL_SCHEMAS]


def get_gemini_tools() -> List[Dict[str, Any]]:
    """Returns schemas compatible with Gemini FunctionDeclaration."""
    return TOOL_SCHEMAS
