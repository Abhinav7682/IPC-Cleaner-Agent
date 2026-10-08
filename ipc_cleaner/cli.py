"""
Command-Line Interface (CLI) and Interactive REPL for IPC Cleaner Agent.
Allows natural language interaction, automated scripting, and audit reporting.
"""

import argparse
import json
import sys
from typing import Optional

from ipc_cleaner.agent import IPCCleanerAgent
from ipc_cleaner.tools.audit import audit_ipc_leaks, get_ipc_summary, list_ipc_resources
from ipc_cleaner.tools.cleaner import purge_abandoned_ipc
from ipc_cleaner.tools.simulator import simulate_ipc_leak


BANNER = r"""
╔══════════════════════════════════════════════════════════════════════╗
║               AGENT #6: IPC CLEANER AGENT (AGENTIC SHELL)            ║
║     Audits & Purges Abandoned System V IPC Leaks (shm, sem, msg)     ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def run_repl(agent: IPCCleanerAgent) -> None:
    """Runs an interactive natural language REPL loop."""
    print(BANNER)
    print("Type your natural language request, or commands like 'summary', 'audit', 'help', 'exit'.\n")

    while True:
        try:
            prompt = input("ipc-agent> ").strip()
            if not prompt:
                continue
            if prompt.lower() in ("exit", "quit", "q"):
                print("Exiting IPC Cleaner Agent. Goodbye!")
                break
            if prompt.lower() == "help":
                print("\nSample queries:")
                print("  • 'Clean up any abandoned shared memory segments taking up RAM.'")
                print("  • 'Dry run cleanup for memory segments with 0 attachments'")
                print("  • 'Audit semaphores and message queues for leaks'")
                print("  • 'Show all active IPC resources'")
                print("  • 'Simulate 2 leaked shared memory segments of 1MB'")
                print("  • 'Get IPC summary'\n")
                continue

            result = agent.handle_query(prompt)
            print()
            print(result["response"])
            print()

        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IPC Cleaner Agent for Linux Agentic Shell - Audits & purges leaked System V IPC resources."
    )
    parser.add_argument("prompt", nargs="*", help="Natural language command to execute.")
    parser.add_argument("--audit", "-a", action="store_true", help="Run IPC leak audit.")
    parser.add_argument("--list", "-l", action="store_true", help="List active IPC resources.")
    parser.add_argument("--summary", "-s", action="store_true", help="Display IPC summary and RAM usage.")
    parser.add_argument("--clean", "-c", action="store_true", help="Purge abandoned IPC resources.")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Perform a dry-run without altering system state.")
    parser.add_argument("--simulate", type=int, metavar="COUNT", help="Simulate COUNT leaked shared memory segments.")
    parser.add_argument("--size-mb", type=int, default=1, help="Size in MB for simulated segments.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON response.")

    args = parser.parse_args()
    agent = IPCCleanerAgent()

    if args.simulate:
        size_bytes = args.size_mb * 1024 * 1024
        res = simulate_ipc_leak(shm_count=args.simulate, size_bytes=size_bytes)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"🧪 [SIMULATED LEAKS] {res.get('message')}")
            print(f"Created SHMID(s): {res.get('created_shm_ids')}")
        return

    if args.summary:
        res = get_ipc_summary()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            shm = res.get("shared_memory", {})
            print(f"📊 IPC Summary: {shm.get('total_segments')} segments ({shm.get('total_ram_human')}) | Leaked: {shm.get('abandoned_segments')} ({shm.get('leaked_ram_human')})")
        return

    if args.list:
        res = list_ipc_resources()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            shm = res.get("shared_memory", [])
            print(f"📋 Found {len(shm)} shared memory segments, {res.get('total_sem_count', 0)} semaphores.")
            for s in shm:
                print(f"  SHMID: {s['id']} | Size: {s['bytes']} bytes | Attachments: {s['nattch']} | Owner: {s['owner']}")
        return

    if args.audit:
        res = audit_ipc_leaks()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"🔍 Audit Report: {res['abandoned_shm_count']} abandoned segments detected. Reclaimable RAM: {res['reclaimable_ram_human']}.")
        return

    if args.clean:
        res = purge_abandoned_ipc(dry_run=args.dry_run)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            shm = res.get("shared_memory", {})
            print(f"🧹 Cleaned {len(shm.get('purged_ids', []))} segments. Reclaimed {res.get('reclaimed_ram_human')}.")
        return

    # If prompt given
    if args.prompt:
        user_query = " ".join(args.prompt)
        res = agent.handle_query(user_query)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(res["response"])
        return

    # Default to REPL if no arguments provided
    run_repl(agent)


if __name__ == "__main__":
    main()
