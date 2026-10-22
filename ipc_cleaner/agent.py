"""
IPC (Inter-Process Communication) Cleaner Agent.
Agent #6 in the next-generation Linux Agentic Shell.
Audits System V IPC (Shared Memory, Message Queues, Semaphores) for leaks
and autonomously cleans abandoned segments with zero attachments.
"""

from datetime import datetime
import json
from typing import Any, Callable, Dict, List, Optional

from ipc_cleaner.llm.provider import LLMClient, SYSTEM_PROMPT
from ipc_cleaner.llm.schemas import TOOL_SCHEMAS
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


class IPCCleanerAgent:
    """
    Domain-Specific Agent for Linux System V IPC Management and Leak Remediation.
    Exposes Linux IPC capabilities as function-calling tools.
    """

    NAME = "ipc_cleaner"
    DESCRIPTION = (
        "Audits System V IPC (Shared Memory, Message Queues, Semaphores) for memory leaks "
        "and purges abandoned segments with zero attachments (nattch=0)."
    )

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.llm = LLMClient(api_key=api_key)
        self.tools: Dict[str, Callable] = {
            "list_ipc_resources": list_ipc_resources,
            "audit_ipc_leaks": audit_ipc_leaks,
            "get_ipc_summary": get_ipc_summary,
            "inspect_ipc_resource": inspect_ipc_resource,
            "purge_shared_memory": purge_shared_memory,
            "purge_message_queues": purge_message_queues,
            "purge_semaphores": purge_semaphores,
            "purge_abandoned_ipc": purge_abandoned_ipc,
            "simulate_ipc_leak": simulate_ipc_leak,
        }
        self.tool_schemas = TOOL_SCHEMAS

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Directly executes a registered tool function with arguments."""
        if tool_name not in self.tools:
            return {
                "status": "error",
                "message": f"Tool '{tool_name}' not recognized by {self.NAME}."
            }

        func = self.tools[tool_name]
        try:
            return func(**arguments)
        except TypeError as e:
            # Fallback if argument mismatch
            return {
                "status": "error",
                "message": f"Argument error calling tool '{tool_name}': {str(e)}"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": f"Execution error in tool '{tool_name}': {str(e)}"
            }

    def handle_query(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Master Agent Loop:
        1. Accepts user natural language prompt.
        2. Queries LLM / Function Calling router.
        3. Executes underlying Linux system operations.
        4. Synthesizes structured outcome and human-readable explanation.
        """
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt}
        ]

        # Call LLM router
        response = self.llm.generate(messages=messages, tools=self.tool_schemas)

        executed_tools: List[Dict[str, Any]] = []

        if response.has_tool_calls:
            for tc in response.tool_calls:
                t_name = tc.get("name")
                t_args = tc.get("arguments", {})
                t_result = self.execute_tool(t_name, t_args)
                executed_tools.append({
                    "tool": t_name,
                    "arguments": t_args,
                    "result": t_result
                })

            summary_text = self._format_agent_response(prompt, executed_tools)
        else:
            summary_text = response.content

        return {
            "agent": self.NAME,
            "prompt": prompt,
            "timestamp": datetime.now().isoformat(),
            "tool_calls": executed_tools,
            "response": summary_text
        }

    def _format_agent_response(self, prompt: str, executed_tools: List[Dict[str, Any]]) -> str:
        """Constructs an informative, engineer-grade terminal report of the actions taken."""
        lines = []

        for item in executed_tools:
            tool_name = item["tool"]
            args = item["arguments"]
            result = item["result"]

            if tool_name == "purge_abandoned_ipc":
                shm_info = result.get("shared_memory", {})
                msg_info = result.get("message_queues", {})
                sem_info = result.get("semaphores", {})

                purged_shm = shm_info.get("purged_ids", [])
                purged_msg = msg_info.get("purged_ids", [])
                purged_sem = sem_info.get("purged_ids", [])

                reclaimed = result.get("reclaimed_ram_human", "0 B")
                is_dry_run = result.get("dry_run", False)

                if is_dry_run:
                    lines.append("🔍 [DRY RUN AUDIT] Scanned System V IPC resources for abandoned leaks:")
                    if purged_shm:
                        lines.append(f"• Candidate SHM IDs (nattch=0): {purged_shm} (Potential RAM to reclaim: {reclaimed})")
                    if purged_msg:
                        lines.append(f"• Candidate Message Queue IDs: {purged_msg}")
                    if purged_sem:
                        lines.append(f"• Candidate Semaphore Set IDs: {purged_sem}")
                    if not purged_shm and not purged_msg and not purged_sem:
                        lines.append("• No abandoned System V IPC resources detected matching criteria.")
                else:
                    total_purged = len(purged_shm) + len(purged_msg) + len(purged_sem)
                    if total_purged > 0:
                        lines.append(f"🧹 [CLEANUP COMPLETE] Successfully purged {total_purged} abandoned System V IPC resource(s):")
                        if purged_shm:
                            lines.append(f"• Purged SHMID(s): {', '.join(str(i) for i in purged_shm)}")
                            lines.append("  Syscalls: ipcrm -m / shmctl(shmid, IPC_RMID)")
                            lines.append(f"  Reclaimed RAM: {reclaimed}")
                        if purged_msg:
                            lines.append(f"• Purged Message Queue(s): {', '.join(str(i) for i in purged_msg)}")
                            lines.append("  Syscalls: ipcrm -q / msgctl(msqid, IPC_RMID)")
                        if purged_sem:
                            lines.append(f"• Purged Semaphore Set(s): {', '.join(str(i) for i in purged_sem)}")
                            lines.append("  Syscalls: ipcrm -s / semctl(semid, IPC_RMID)")
                    else:
                        lines.append("✅ [CLEANUP CHECK] Scanned System V IPC: No abandoned resources detected.")

            elif tool_name == "purge_shared_memory":
                purged = result.get("purged_ids", [])
                failed = result.get("failed_ids", {})
                reclaimed = result.get("reclaimed_bytes_human", "0 B")
                lines.append(f"🧹 Purged shared memory segments {purged}. Reclaimed {reclaimed}.")
                if failed:
                    lines.append(f"⚠️ Failed to purge: {failed}")

            elif tool_name == "purge_message_queues":
                purged = result.get("purged_ids", [])
                failed = result.get("failed_ids", {})
                reclaimed = result.get("reclaimed_bytes_human", "0 B")
                lines.append(f"🧹 Purged message queue(s) {purged}. Reclaimed buffer bytes: {reclaimed}.")
                if failed:
                    lines.append(f"⚠️ Failed to purge: {failed}")

            elif tool_name == "purge_semaphores":
                purged = result.get("purged_ids", [])
                failed = result.get("failed_ids", {})
                lines.append(f"🧹 Purged semaphore set(s) {purged}.")
                if failed:
                    lines.append(f"⚠️ Failed to purge: {failed}")

            elif tool_name == "audit_ipc_leaks":
                reclaimable = result.get("reclaimable_ram_human", "0 B")
                leaked_shm = result.get("abandoned_shm", [])
                leaked_msg = result.get("abandoned_msg", [])
                leaked_sem = result.get("abandoned_sem", [])

                lines.append("🔍 [AUDIT REPORT] System V IPC Leak Analysis:")
                lines.append(f"• Total SHM: {result.get('total_shm_count')} | Abandoned (nattch=0): {len(leaked_shm)} | Reclaimable RAM: {reclaimable}")
                for s in leaked_shm:
                    lines.append(f"  - SHMID {s.get('id')} ({s.get('bytes')} bytes) | Owner: {s.get('owner')} | Confidence: {s.get('leak_confidence')}")

                if leaked_msg:
                    lines.append(f"• Abandoned Message Queues: {len(leaked_msg)}")
                    for m in leaked_msg:
                        lines.append(f"  - MSQID {m.get('id')} (Msgs: {m.get('messages')}, Bytes: {m.get('used_bytes')}) | Confidence: {m.get('leak_confidence')}")

                if leaked_sem:
                    lines.append(f"• Abandoned Semaphores: {len(leaked_sem)}")
                    for sm in leaked_sem:
                        lines.append(f"  - SEMID {sm.get('id')} (NSEMS: {sm.get('nsems')}) | Owner: {sm.get('owner')} | Confidence: {sm.get('leak_confidence')}")

            elif tool_name == "get_ipc_summary":
                shm_stat = result.get("shared_memory", {})
                lines.append("📊 [IPC SUBSYSTEM SUMMARY]")
                lines.append(f"• Active Shared Memory: {shm_stat.get('total_segments')} segments ({shm_stat.get('total_ram_human')})")
                lines.append(f"• Abandoned SHM: {shm_stat.get('abandoned_segments')} segments ({shm_stat.get('leaked_ram_human')} reclaimable)")
                lines.append(f"• Message Queues: {result.get('message_queues', {}).get('total_queues', 0)}")
                lines.append(f"• Semaphores: {result.get('semaphores', {}).get('total_sets', 0)}")

            elif tool_name == "list_ipc_resources":
                shm_items = result.get("shared_memory", [])
                msg_items = result.get("message_queues", [])
                sem_items = result.get("semaphores", [])

                lines.append(f"📋 [ACTIVE IPC RESOURCES] ({result.get('filter')})")
                if shm_items:
                    lines.append(f"Shared Memory ({len(shm_items)}):")
                    for s in shm_items:
                        lines.append(f"  ID: {s.get('id')} | Key: {s.get('key')} | Owner: {s.get('owner')} | Bytes: {s.get('bytes')} | Attachments: {s.get('nattch')}")
                if msg_items:
                    lines.append(f"Message Queues ({len(msg_items)}):")
                    for m in msg_items:
                        lines.append(f"  ID: {m.get('id')} | Key: {m.get('key')} | Owner: {m.get('owner')} | Messages: {m.get('messages')} | Bytes: {m.get('used_bytes')}")
                if sem_items:
                    lines.append(f"Semaphores ({len(sem_items)}):")
                    for sm in sem_items:
                        lines.append(f"  ID: {sm.get('id')} | Key: {sm.get('key')} | Owner: {sm.get('owner')} | NSEMS: {sm.get('nsems')}")

            elif tool_name == "simulate_ipc_leak":
                lines.append(f"🧪 [SIMULATION] {result.get('message')}")
                if result.get("created_shm_ids"):
                    lines.append(f"• Created SHM IDs: {result.get('created_shm_ids')} ({result.get('total_leaked_ram_human')})")
                if result.get("created_msg_ids"):
                    lines.append(f"• Created MSQ IDs: {result.get('created_msg_ids')}")
                if result.get("created_sem_ids"):
                    lines.append(f"• Created SEM IDs: {result.get('created_sem_ids')}")

            else:
                lines.append(f"Executed tool '{tool_name}': {json.dumps(result, indent=2)}")

        return "\n".join(lines)
