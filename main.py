#!/usr/bin/env python3
"""
ApexHunter - Enterprise EDR Entry Point
Handles UAC privilege escalation and application bootstrap.
"""

import sys
import os
import ctypes


def is_elevated() -> bool:
    """
    Determine if the current process token has Administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def escalate_uac():
    """
    Re-launch the current script with elevated privileges via ShellExecuteW.
    """
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )


if __name__ == "__main__":
    if not is_elevated():
        escalate_uac()
        sys.exit(0)

    project_root = os.path.dirname(os.path.abspath(__file__))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from app import ApexHunterGUI
    app = ApexHunterGUI()
    app.run()
