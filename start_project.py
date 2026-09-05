#!/usr/bin/env python3
"""
Project Launcher - Starts all required components in separate terminals.
"""

import os
import sys
import subprocess
import time

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_ACTIVATE = os.path.join(PROJECT_DIR, "venv", "Scripts", "activate.bat")  # Windows

def open_terminal(title, command):
    """Open a new terminal window and run the command."""
    if sys.platform == "win32":
        cmd = f'start "{title}" cmd /k "cd /d {PROJECT_DIR} && {VENV_ACTIVATE} && {command}"'
        subprocess.Popen(cmd, shell=True)
    else:  # Linux/Mac
        # Use xterm or gnome-terminal if available
        subprocess.Popen(["xterm", "-T", title, "-e", f"cd {PROJECT_DIR} && source venv/bin/activate && {command}"])

def main():
    print("🛡️  URL Security System Launcher")
    print("=" * 40)

    # Check if venv exists
    if not os.path.exists(VENV_ACTIVATE):
        print("❌ Virtual environment not found. Please create it first.")
        sys.exit(1)

    # Start API Server
    print("[1/3] Starting API Server...")
    open_terminal("URL-Security-API", "python scripts/run_api.py")
    time.sleep(3)

    # Start Dashboard
    print("[2/3] Starting Dashboard...")
    open_terminal("URL-Security-Dashboard", "streamlit run dashboard/app.py")
    time.sleep(2)

    # Ask about live monitor
    choice = input("Start Live Monitor? (y/n): ").strip().lower()
    if choice == 'y':
        print("[3/3] Starting Live Monitor...")
        open_terminal("URL-Security-Live-Monitor", "python scripts/live_monitor.py")
    else:
        print("[3/3] Live Monitor skipped.")

    print("\n✅ Project Started!")
    print("   Dashboard: http://localhost:8501")
    print("   API Docs:  http://localhost:8001/docs")

if __name__ == "__main__":
    main()