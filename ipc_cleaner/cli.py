"""
Command-Line Interface (CLI) and Interactive REPL for IPC Cleaner Agent.
Allows natural language interaction, automated scripting, and audit reporting.
"""

import argparse
import json
import os
import sys
from typing import Optional

# Ensure repository root is in sys.path when executed directly
_repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


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
    parser.add_argument("--type", "-t", choices=["shm", "msg", "sem", "all"], default="all",
                        help="Filter by IPC resource type: 'shm' (shared memory), 'msg' (message queues), 'sem' (semaphores), or 'all' (default).")
    parser.add_argument("--dry-run", "-d", action="store_true", help="Perform a dry-run without altering system state.")
    parser.add_argument("--simulate", type=int, metavar="COUNT", default=None, help="Simulate COUNT leaked shared memory segments.")
    parser.add_argument("--sem", type=int, default=0, metavar="COUNT", help="Count of semaphores to simulate.")
    parser.add_argument("--msg", type=int, default=0, metavar="COUNT", help="Count of message queues to simulate.")
    parser.add_argument("--size-mb", type=int, default=1, help="Size in MB for simulated segments.")
    parser.add_argument("--json", action="store_true", help="Output raw JSON response.")

    args = parser.parse_args()
    agent = IPCCleanerAgent()

    if args.simulate is not None or args.sem > 0 or args.msg > 0:
        shm_cnt = args.simulate if args.simulate is not None else 0
        size_bytes = args.size_mb * 1024 * 1024
        res = simulate_ipc_leak(shm_count=shm_cnt, size_bytes=size_bytes, sem_count=args.sem, msg_count=args.msg)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"🧪 [SIMULATED LEAKS] {res.get('message')}")
            if res.get("created_shm_ids"):
                print(f"  Created SHMID(s): {res.get('created_shm_ids')}")
            if res.get("created_sem_ids"):
                print(f"  Created SEMID(s): {res.get('created_sem_ids')}")
            if res.get("created_msg_ids"):
                print(f"  Created MSQID(s): {res.get('created_msg_ids')}")
        return

    if args.summary:
        res = get_ipc_summary()
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            shm = res.get("shared_memory", {})
            msg = res.get("message_queues", {})
            sem = res.get("semaphores", {})
            print("📊 IPC Subsystem Summary:")
            print(f"  • Shared Memory : {shm.get('total_segments', 0)} segments ({shm.get('total_ram_human', '0 B')}) | Abandoned: {shm.get('abandoned_segments', 0)} ({shm.get('leaked_ram_human', '0 B')})")
            print(f"  • Message Queues: {msg.get('total_queues', 0)} queues | Abandoned: {msg.get('abandoned_queues', 0)}")
            print(f"  • Semaphores    : {sem.get('total_sets', 0)} sets | Abandoned: {sem.get('abandoned_sets', 0)}")
        return

    if args.list:
        res = list_ipc_resources(resource_type=args.type)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            shm = res.get("shared_memory", [])
            msg = res.get("message_queues", [])
            sem = res.get("semaphores", [])
            print(f"📋 Active IPC Resources (Filter: {args.type.upper()}):")
            if args.type in ("shm", "all"):
                print(f"\n  [Shared Memory Segments ({len(shm)}) | Total RAM: {res.get('total_shm_human', '0 B')}]")
                if not shm:
                    print("    (none)")
                for s in shm:
                    print(f"    SHMID: {s['id']:<8} | Size: {s['bytes_human']:<10} | Attachments: {s['nattch']:<4} | Owner: {s['owner']}")
            if args.type in ("msg", "all"):
                print(f"\n  [Message Queues ({len(msg)})]")
                if not msg:
                    print("    (none)")
                for m in msg:
                    print(f"    MSQID: {m['id']:<8} | Messages: {m['messages']:<6} | Used: {m['bytes_used']:<6} B | Owner: {m['owner']}")
            if args.type in ("sem", "all"):
                print(f"\n  [Semaphore Sets ({len(sem)})]")
                if not sem:
                    print("    (none)")
                for s in sem:
                    print(f"    SEMID: {s['id']:<8} | Semaphores: {s['nsems']:<4} | Waiters: {s.get('nwaiters', 0):<4} | Owner: {s['owner']}")
        return

    if args.audit:
        res = audit_ipc_leaks(resource_type=args.type)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            print(f"🔍 IPC Leak Audit Report (Filter: {args.type.upper()}):")
            print(f"  • Abandoned SHM Segments : {res['abandoned_shm_count']} ({res['reclaimable_ram_human']} reclaimable)")
            print(f"  • Abandoned Message Queues: {res['abandoned_msg_count']}")
            print(f"  • Abandoned Semaphore Sets: {res['abandoned_sem_count']}")
            if res.get("abandoned_shm"):
                print("\n  [Detected Leaked Shared Memory]")
                for s in res["abandoned_shm"]:
                    print(f"    SHMID: {s['id']} | Size: {s['bytes_human']} | Confidence: {s['leak_confidence']} | Reason: {s['leak_reason']}")
            if res.get("abandoned_msg"):
                print("\n  [Detected Leaked Message Queues]")
                for m in res["abandoned_msg"]:
                    print(f"    MSQID: {m['id']} | Msgs: {m['messages']} | Confidence: {m['leak_confidence']} | Reason: {m['leak_reason']}")
            if res.get("abandoned_sem"):
                print("\n  [Detected Leaked Semaphores]")
                for s in res["abandoned_sem"]:
                    print(f"    SEMID: {s['id']} | Nsems: {s['nsems']} | Waiters: {s.get('nwaiters', 0)} | Confidence: {s['leak_confidence']} | Reason: {s['leak_reason']}")
            if res["abandoned_shm_count"] == 0 and res["abandoned_msg_count"] == 0 and res["abandoned_sem_count"] == 0:
                print("\n  ✅ No abandoned or leaked IPC resources detected.")
        return

    if args.clean:
        res = purge_abandoned_ipc(resource_type=args.type, dry_run=args.dry_run)
        if args.json:
            print(json.dumps(res, indent=2))
        else:
            mode = "DRY-RUN (Preview)" if args.dry_run else "PURGE (Executed)"
            print(f"🧹 IPC Cleanup [{mode}] (Filter: {args.type.upper()}):")
            shm_res = res.get("shared_memory", {})
            msg_res = res.get("message_queues", {})
            sem_res = res.get("semaphores", {})
            purged_shm = shm_res.get("purged_ids", [])
            purged_msg = msg_res.get("purged_ids", [])
            purged_sem = sem_res.get("purged_ids", [])
            print(f"  • Reclaimed RAM    : {res.get('reclaimed_ram_human', '0 B')}")
            print(f"  • SHM Segments ({len(purged_shm)}) : {purged_shm if purged_shm else 'None'}")
            print(f"  • Message Queues ({len(purged_msg)}): {purged_msg if purged_msg else 'None'}")
            print(f"  • Semaphores ({len(purged_sem)})    : {purged_sem if purged_sem else 'None'}")
            failed = {**shm_res.get("failed_ids", {}), **msg_res.get("failed_ids", {}), **sem_res.get("failed_ids", {})}
            if failed:
                print(f"  ⚠️ Failures/Locks: {failed}")
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
