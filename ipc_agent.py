#!/usr/bin/env python3
"""
Top-level entrypoint for the IPC Cleaner Agent.
Can be executed directly from shell: ./ipc_agent.py "Clean up any abandoned shared memory segments taking up RAM."
"""

import sys
from ipc_cleaner.cli import main

if __name__ == "__main__":
    main()
