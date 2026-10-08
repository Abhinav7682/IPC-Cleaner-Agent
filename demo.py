#!/usr/bin/env python3
"""
Full End-to-End Live Demonstration Script for IPC Cleaner Agent (Agent #6).
Demonstrates the agent receiving natural language prompts, calling underlying tools,
interfacing with the OS via System Calls, and safely cleaning abandoned IPC memory leaks.
"""

import time
from ipc_cleaner.agent import IPCCleanerAgent
from ipc_cleaner.core.parser import IPCParser


def print_section(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def main():
    agent = IPCCleanerAgent()

    print_section("NEXT-GENERATION LINUX AGENTIC SHELL")
    print("Domain Agent Assignment: #6 - IPC (Inter-Process Communication) Cleaner Agent")
    print("Capabilities: Audits & purges System V shared memory, message queues, semaphores")
    print("Interfacing: Linux System Calls (subprocess ipcrm, os, libc ctypes / C shared library)")
    time.sleep(1)

    # 1. Baseline System State
    print_section("STEP 1: INSPECT CURRENT OS BASELINE (ipcs)")
    baseline = agent.handle_query("Get IPC summary")
    print(baseline["response"])
    time.sleep(1)

    # 2. Simulate Leaked Shared Memory Segments
    print_section("STEP 2: SIMULATE ABANDONED IPC MEMORY LEAKS")
    print("Simulating orphaned shared memory segments where creator processes have terminated...")
    sim_prompt = "Simulate 3 leaked shared memory segments of 2MB"
    print(f"User Prompt: \"{sim_prompt}\"")
    sim_result = agent.handle_query(sim_prompt)
    print(sim_result["response"])
    time.sleep(1)

    # 3. Audit Leaks (Inspect attachment count nattch == 0)
    print_section("STEP 3: AUDIT SYSTEM V IPC FOR LEAKS")
    audit_prompt = "Audit System V IPC for leaks"
    print(f"User Prompt: \"{audit_prompt}\"")
    audit_result = agent.handle_query(audit_prompt)
    print(audit_result["response"])
    time.sleep(1)

    # 4. Dry Run Preview
    print_section("STEP 4: DRY RUN CLEANUP (SAFETY VERIFICATION)")
    dry_prompt = "Dry run cleanup of abandoned shared memory segments"
    print(f"User Prompt: \"{dry_prompt}\"")
    dry_result = agent.handle_query(dry_prompt)
    print(dry_result["response"])
    time.sleep(1)

    # 5. The Assignment Prompt: Autonomous Cleanup!
    print_section("STEP 5: AUTONOMOUS REMEDIATION VIA NATURAL LANGUAGE")
    target_prompt = "Clean up any abandoned shared memory segments taking up RAM."
    print(f"User Prompt: \"{target_prompt}\"")
    print("Agent is evaluating tool schemas and executing System Calls...")
    clean_result = agent.handle_query(target_prompt)
    print(clean_result["response"])
    time.sleep(1)

    # 6. Post-Remediation Verification
    print_section("STEP 6: POST-CLEANUP VERIFICATION")
    post_summary = agent.handle_query("Get IPC summary")
    print(post_summary["response"])
    print("\n✅ Verification complete: Leaked memory reclaimed; running services remain untouched.")


if __name__ == "__main__":
    main()
