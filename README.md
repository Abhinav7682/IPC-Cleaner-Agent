# IPC-Cleaner-Agent
# 🧹 Agent #6: IPC (Inter-Process Communication) Cleaner Agent

An autonomous, domain-specific systems administration agent built for the next-generation **Linux Agentic Shell**. Instead of forcing users to memorize complex commands like `ipcs -m`, `ipcs -p`, or `ipcrm -m <shmid>`, this agent accepts natural language commands, decides which system tools to invoke via LLM Function Calling, and interfaces directly with the Real-Time OS via **System Calls (`os`, `subprocess`, `libc`)** to safely audit and clean abandoned IPC resources.

---

## 📌 Problem Context: Why IPC Leaks Occur in Linux

In Linux and Unix systems, **System V IPC objects** (Shared Memory Segments, Message Queues, Semaphores) and POSIX IPC objects persist in kernel memory across process lifecycles. If a process (such as a database, web server, build tool, or crashed user program) terminates abruptly without calling `shmctl(shmid, IPC_RMID, NULL)`, the shared memory segments remain allocated in physical RAM.

These orphaned segments:
- Continue consuming physical RAM and swap space.
- Have **zero attached processes (`nattch == 0`)**.
- Have terminated or non-existent creator processes (**dead CPID**).
- Exhaust system-wide IPC identifier limits (`SHMMNI`, `SEMMNI`, `MSGMNI`).

The **IPC Cleaner Agent** solves this by autonomously auditing the IPC subsystem, diagnosing abandoned resources with zero attachments, and executing safe kernel cleanups.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Linux Agentic Shell: Master Loop                     │
│               Accepts User Natural Language Command                   │
│             e.g., "Clean up any abandoned shared memory"               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                       LLM Intent Classification
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│             Agent #6: IPC Cleaner Agent (IPCCleanerAgent)             │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                    LLM Function Calling Layer                  │   │
│   │   Selects optimal tool based on prompt & parameter schemas     │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │                 Linux IPC Capabilities (Tools)                 │   │
│   │  • audit_ipc_leaks()        • purge_abandoned_ipc()            │   │
│   │  • purge_shared_memory()    • list_ipc_resources()             │   │
│   │  • get_ipc_summary()        • simulate_ipc_leak()              │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│                                   ▼                                    │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │              Real-Time OS Interfacing & Safeguards             │   │
│   │  1. Inspection:  `ipcs -a` / `/proc/sysvipc/` / `psutil`      │   │
│   │  2. Safety Lock: Enforces `nattch == 0` & PID liveness check   │   │
│   │  3. Execution:   `ipcrm` via `subprocess` & `libc` Syscalls    │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
└───────────────────────────────────┼────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                    Linux Real-Time Operating System                    │
│   shmctl(shmid, IPC_RMID) / ipcrm -m <id> -> Physical RAM Reclaimed   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Linux Capabilities Defined as Tools (Function Calling)

All tools are exposed with standard JSON schemas compatible with Google Gemini Function Declarations, OpenAI Tool Call specifications, and local semantic routing.

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| **`purge_abandoned_ipc`** | `resource_type`, `dry_run`, `min_confidence`, `force` | **Primary Autonomous Tool**: Audits System V IPC, detects zero-attachment (`nattch=0`) segments whose creator PIDs are dead, and purges them to reclaim RAM. |
| **`audit_ipc_leaks`** | `resource_type`, `min_confidence`, `only_zero_attachments` | Audits the system for abandoned segments, semaphores, and queues; calculates reclaimable RAM and flags confidence levels. |
| **`purge_shared_memory`** | `shm_ids`, `dry_run`, `force` | Removes specific shared memory segment IDs. Protected by the **Active Attachment Safety Lock**. |
| **`purge_semaphores`** | `sem_ids`, `dry_run`, `force` | Removes specified semaphore sets via `ipcrm -s` / `semctl`. |
| **`purge_message_queues`** | `msg_ids`, `dry_run`, `force` | Removes specified message queues via `ipcrm -q` / `msgctl`. |
| **`list_ipc_resources`** | `resource_type` | Lists all active IPC resources, sizes, owners, keys, and attachment counts. |
| **`get_ipc_summary`** | *(none)* | Provides a high-level summary of total shared memory RAM, leaked RAM, and kernel IPC limits. |
| **`inspect_ipc_resource`**| `resource_type`, `resource_id` | Performs deep inspection of a specific segment, including timestamps and process metadata. |
| **`simulate_ipc_leak`** | `shm_count`, `size_bytes`, `sem_count`, `msg_count` | Benchmarking/grading utility that creates controlled orphaned IPC objects whose creator process immediately exits. |

---

## ⚙️ Real-Time OS Interfacing via System Calls

The agent interfaces with the operating system through multiple layers:

1. **Subprocess & Command Parsing (`ipcs`)**:
   - Universal parser supporting Linux `util-linux` tables as well as BSD/macOS `ipcs -a`.
   - Direct kernel procfs parser: reads Linux `/proc/sysvipc/shm`, `/proc/sysvipc/msg`, and `/proc/sysvipc/sem` directly without spawning subshells when running on Linux.
2. **Subprocess Command Execution (`ipcrm`)**:
   - Executes `ipcrm -m <shmid>`, `ipcrm -q <msqid>`, and `ipcrm -s <semid>`.
3. **Direct C `libc` System Calls (`ctypes` and native C library)**:
   - Direct invocation of:
     - `shmctl(shmid, IPC_RMID, NULL)`
     - `semctl(semid, 0, IPC_RMID)`
     - `msgctl(msqid, IPC_RMID, NULL)`
     - `shmctl(shmid, IPC_STAT, &ds)`
   - Includes a native C implementation in `c_src/ipc_ops.c` and header `c_src/ipc_ops.h` compiled into `bin/libipc_ops.dylib` / `bin/libipc_ops.so`.
4. **Process Liveness Verification**:
   - Resolves creator PID (`cpid`) and last operator PID (`lpid`).
   - Inspects `/proc/<pid>/status` and `/proc/<pid>/cmdline`, `psutil`, or `os.kill(pid, 0)` to reliably distinguish between alive processes, defunct zombie processes, and terminated processes.

---

## 🛡️ Safety Architecture

Deleting IPC resources indiscriminately can crash active production services (such as PostgreSQL, Redis, or Apache). The IPC Cleaner Agent implements multi-tier protections across all System V subsystems:

1. **Active Attachment Lock (`nattch > 0` for Shared Memory)**:
   - The agent strictly checks the current attachment count. If `nattch > 0`, the segment is locked and deletion is refused unless explicit `force=True` is provided.
2. **Active Process Waiter Lock (`nwaiters > 0` for Semaphores)**:
   - Evaluates `semctl(semid, semnum, GETNCNT)` and `GETZCNT`. If processes are actively suspended waiting for semaphore state changes, deletion is locked to prevent concurrency corruption.
3. **Unread Message Buffer Lock (`messages > 0` for Message Queues)**:
   - If a queue contains buffered, unconsumed messages, deletion is refused without explicit `force=True`.
4. **Process Liveness Correlation**:
   - A resource is only marked as a high-confidence leak if active attachments/waiters are zero **AND** the creator or last operator process has terminated or exited.
5. **Dry Run Support**:
   - Users can preview what resources will be deleted and calculate potential memory savings without modifying system state by issuing prompts like *"Dry run cleanup of abandoned IPC resources"*.

---

## 📁 Repository Structure

```
IPC-Cleaner-Agent/
├── README.md                      # Comprehensive documentation
├── Makefile                       # Build, test, demo, and clean targets
├── requirements.txt               # Dependencies (pydantic, rich, psutil, pytest)
├── ipc_agent.py                   # Standalone executable CLI entrypoint
├── demo.py                        # Live interactive end-to-end demonstration
├── demo_base_shell.py             # Base Shell master loop router simulation
├── bin/                           # Compiled C binaries
│   ├── leak_generator             # C binary to simulate orphaned IPC leaks
│   └── libipc_ops.dylib (.so)     # Compiled C IPC shared library
├── c_src/                         # Low-level C sources
│   ├── ipc_ops.h                  # C header for low-level IPC syscalls
│   ├── ipc_ops.c                  # C implementation of shmctl, semctl, msgctl
│   └── test_leak_generator.c      # C test harness to simulate abandoned leaks
├── ipc_cleaner/                   # Python package
│   ├── __init__.py
│   ├── agent.py                   # IPCCleanerAgent main class & loop
│   ├── cli.py                     # Rich CLI with --type (shm, msg, sem, all)
│   ├── base_shell_adapter.py      # Base Shell integration contract & adapter
│   ├── models.py                  # Pydantic models (ShmSegment, SemaphoreSet, etc.)
│   ├── core/                      # OS interface layer
│   │   ├── parser.py              # Universal ipcs & /proc/sysvipc parser
│   │   ├── executor.py            # ipcrm & libc syscall safe executor
│   │   ├── syscalls.py            # ctypes libc system call wrappers
│   │   └── process.py             # Process liveness & PID metadata resolver
│   ├── tools/                     # Function Calling Tools
│   │   ├── audit.py               # audit_ipc_leaks, list_ipc_resources, etc.
│   │   ├── cleaner.py             # purge_abandoned_ipc, purge_semaphores, etc.
│   │   └── simulator.py           # simulate_ipc_leak test harness
│   └── llm/                       # LLM & Function Calling Layer
│       ├── provider.py            # Gemini, OpenAI, & Local Semantic Router
│       └── schemas.py             # JSON schemas for function declarations
└── tests/                         # Full automated test suite (25 tests)
    ├── test_parser.py             # Unit tests for Linux and Darwin parsers
    ├── test_syscalls.py           # Unit tests for raw libc syscalls
    ├── test_tools.py              # Unit tests for individual agent tools & safety locks
    ├── test_agent.py              # Unit tests for natural language intent routing
    ├── test_system_v_full.py      # Full System V coverage: SEM & MSG procfs, locks, E2E
    └── test_e2e_simulation.py     # End-to-end leak, audit, and purge lifecycle test
```

---

## 🚀 Quickstart & Usage

### 1. Build and Run Tests
```bash
# Build C helpers and run the test suite
make test
```
*Output: 25 passed tests in ~0.5s.*

### 2. Run the Live End-to-End Demo
```bash
make demo
```
This runs a multi-step demonstration:
1. Inspects the current OS baseline.
2. Injects 2 MB of realistic abandoned shared memory via C helper.
3. Audits the system for leaks and identifies `nattch=0` with dead creator PID.
4. Performs a dry-run preview.
5. Executes the assignment command: *"Clean up any abandoned shared memory segments taking up RAM."*
6. Confirms memory is reclaimed and active services remain untouched.

### 3. Run the Base Shell Integration Demo
```bash
make base-shell
```
Demonstrates how the class-wide Base Shell master loop dispatches natural language queries to Agent #6.

### 4. Interactive Agent Shell (REPL)
Launch the interactive agent shell:
```bash
./ipc_agent.py
```
```
╔══════════════════════════════════════════════════════════════════════╗
║               AGENT #6: IPC CLEANER AGENT (AGENTIC SHELL)            ║
║     Audits & Purges Abandoned System V IPC Leaks (shm, sem, msg)     ║
╚══════════════════════════════════════════════════════════════════════╝

ipc-agent> Clean up any abandoned shared memory segments taking up RAM.

🧹 [CLEANUP COMPLETE] Successfully purged 2 abandoned shared memory segment(s):
• Purged SHMID(s): 393217, 131074
• System Calls executed: ipcrm -m / shmctl(shmid, IPC_RMID)
• Reclaimed RAM: 2.00 MB
```

### 5. Single-Shot CLI Commands
```bash
# Natural Language execution
./ipc_agent.py "Clean up any abandoned shared memory segments taking up RAM."
./ipc_agent.py "Dry run cleanup of abandoned shared memory segments"
./ipc_agent.py "Audit System V IPC for memory leaks"

# Direct diagnostic flags
./ipc_agent.py --summary
./ipc_agent.py --list
./ipc_agent.py --audit
./ipc_agent.py --simulate 3 --size-mb 2
```

---

## 🧪 Test Suite Verification

Run all automated unit and integration tests:
```bash
python3 -m pytest tests/ -v
```

Verified test coverage:
- ✅ `test_parse_linux_ipcs`: Linux util-linux format parsing & section handling
- ✅ `test_parse_darwin_ipcs`: Darwin / BSD `ipcs -a` format parsing
- ✅ `test_shm_create_and_destroy`: Direct `libc` `shmget` & `shmctl(IPC_RMID)` syscalls
- ✅ `test_sem_create_and_destroy`: Direct `libc` `semget` & `semctl(IPC_RMID)` syscalls
- ✅ `test_msg_create_and_destroy`: Direct `libc` `msgget` & `msgctl(IPC_RMID)` syscalls
- ✅ `test_safety_check_prevents_active_segment_purge`: Attachment safety lock prevents killing active segments (`nattch > 0`)
- ✅ `test_dry_run_does_not_destroy_segment`: Dry-run mode previews without destroying segments
- ✅ `test_list_ipc_resources`: Structure and formatting of active resources
- ✅ `test_audit_ipc_leaks`: Quantitative leak reporting and RAM calculation
- ✅ `test_get_ipc_summary`: High-level subsystem usage statistics
- ✅ `test_clean_abandoned_prompt_routing`: Natural language routing for cleanup
- ✅ `test_dry_run_prompt_routing`: Natural language routing for dry-run
- ✅ `test_audit_prompt_routing`: Natural language routing for audit
- ✅ `test_list_prompt_routing`: Natural language routing for list
- ✅ `test_summary_prompt_routing`: Natural language routing for summary
- ✅ `test_e2e_leak_and_remediation_lifecycle`: Complete lifecycle: leak injection -> audit -> dry-run -> purge -> OS verification