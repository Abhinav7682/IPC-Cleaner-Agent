"""
Base Shell Adapter for integrating the IPC Cleaner Agent into the class-wide
35-agent Linux Agentic Shell architecture.
"""

from typing import Any, Callable, Dict, Optional
from ipc_cleaner.agent import IPCCleanerAgent


class BaseShellAgentInterface:
    """Standard protocol contract expected by the class-wide Base Shell."""

    def __init__(self, agent_id: int = 6, name: str = "ipc_cleaner"):
        self.agent_id = agent_id
        self.name = name

    def get_capabilities(self) -> Dict[str, Any]:
        """Returns registration metadata for the Base Shell LLM router."""
        raise NotImplementedError

    def handle(self, prompt: str, session_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Executes the agent logic on routed prompt."""
        raise NotImplementedError


class IPCCleanerBaseShellAdapter(BaseShellAgentInterface):
    """
    Adapter implementing the BaseShell interface for Agent #6 (IPC Cleaner).
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(agent_id=6, name="ipc_cleaner")
        self.agent = IPCCleanerAgent(api_key=api_key)

    def get_capabilities(self) -> Dict[str, Any]:
        """Returns routing metadata and tool definitions for the Base Shell router."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "domain": "Linux Inter-Process Communication (IPC)",
            "description": (
                "Audits and remediates System V and POSIX IPC resource leaks. "
                "Detects and cleans up abandoned shared memory segments (nattch=0), "
                "orphaned semaphores, and message queues to reclaim physical RAM."
            ),
            "sample_prompts": [
                "Clean up any abandoned shared memory segments taking up RAM.",
                "Audit System V IPC for memory leaks.",
                "Show all shared memory segments with zero attachments.",
                "Dry run cleanup of orphaned IPC resources.",
                "Purge shared memory segment 12345."
            ],
            "keywords": [
                "ipc", "ipcs", "ipcrm", "shm", "shared memory", "sem", "semaphore",
                "msq", "message queue", "nattch", "attachments", "reclaim ram", "sysvipc"
            ],
            "tools": self.agent.tool_schemas
        }

    def handle(self, prompt: str, session_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Routes prompt to agent and returns formatted response to Base Shell."""
        return self.agent.handle_query(prompt, context=session_context)


def register_with_base_shell(registry: Dict[str, Any]) -> None:
    """Helper for registering this agent into an external Base Shell agent registry."""
    adapter = IPCCleanerBaseShellAdapter()
    registry["ipc_cleaner"] = adapter
    registry[6] = adapter
