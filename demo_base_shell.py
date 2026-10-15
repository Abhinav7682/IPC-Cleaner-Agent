"""
Demonstration of the Base Shell Master Loop integrating with Agent #6 (IPC Cleaner).
Shows how the Base Shell routes natural language user text to specialized agents.
"""

import sys
from typing import Any, Dict

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from ipc_cleaner.base_shell_adapter import IPCCleanerBaseShellAdapter



class DemoBaseShell:
    """
    Mock Base Shell architecture showcasing how user text routes to
    domain-specific agents (Agent #6 in our assignment).
    """

    def __init__(self):
        self.agents: Dict[int, Any] = {}
        # Register Agent #6
        self.register_agent(IPCCleanerBaseShellAdapter())

    def register_agent(self, adapter: Any) -> None:
        self.agents[adapter.agent_id] = adapter

    def route_and_execute(self, user_text: str) -> None:
        print(f"\n[BASE SHELL] Received query: \"{user_text}\"")
        print("[BASE SHELL] Running LLM Intent Router...")

        # Domain classification: Check against Agent #6 capabilities
        agent_6 = self.agents[6]
        caps = agent_6.get_capabilities()

        # Check if text matches IPC domain
        user_lower = user_text.lower()
        is_ipc_match = any(kw in user_lower for kw in caps["keywords"]) or \
                       any(kw in user_lower for kw in ["clean", "shared memory", "ram", "leak", "segments"])

        if is_ipc_match:
            print(f"[BASE SHELL] -> Routing intent to Agent #6 ({caps['name']}: {caps['domain']})")
            print(f"[BASE SHELL] -> Invoking Agent #{caps['agent_id']} via BaseShellAdapter...")
            response = agent_6.handle(user_text)

            print("\n" + "=" * 60)
            print(f"[AGENT #6 OUTPUT]")
            print("=" * 60)
            print(response["response"])
            print("=" * 60 + "\n")
        else:
            print(f"[BASE SHELL] Query not matched to Agent #6 (IPC Cleaner). Routed to other agents.")


def main():
    shell = DemoBaseShell()

    scenarios = [
        "Simulate 2 leaked shared memory segments of 1MB",
        "Clean up any abandoned shared memory segments taking up RAM.",
        "Get IPC summary and check system memory limits"
    ]

    print("══════════════════════════════════════════════════════════════")
    print("   AGENTIC SHELL ARCHITECTURE - BASE SHELL DISPATCH DEMO       ")
    print("══════════════════════════════════════════════════════════════")

    for prompt in scenarios:
        shell.route_and_execute(prompt)


if __name__ == "__main__":
    main()
