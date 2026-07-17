#!/usr/bin/env python3
"""
ApexHunter - Enterprise EDR Entry Point
Handles UAC privilege escalation and application bootstrap.
"""

import sys
import os
import ctypes
from ctypes import wintypes


def is_elevated() -> bool:
    """
    Determine if the current process token has the Administrator SID.
    Uses CheckTokenMembership to avoid shell32 dependency where possible.
    """
    SECURITY_NT_AUTHORITY = (0, 0, 0, 0, 0, 5)

    class SID_IDENTIFIER_AUTHORITY(ctypes.Structure):
        _fields_ = [("Value", ctypes.c_ubyte * 6)]

    sid = wintypes.PSID()
    sia = SID_IDENTIFIER_AUTHORITY()
    sia.Value = SECURITY_NT_AUTHORITY

    alloc = ctypes.windll.advapi32.AllocateAndInitializeSid
    alloc.argtypes = [
        ctypes.POINTER(SID_IDENTIFIER_AUTHORITY), ctypes.c_byte,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(wintypes.PSID)
    ]
    alloc.restype = wintypes.BOOL

    if not alloc(ctypes.byref(sia), 2, 32, 544, 0, 0, 0, 0, 0, 0, ctypes.byref(sid)):
        return False

    try:
        member = wintypes.BOOL()
        if ctypes.windll.advapi32.CheckTokenMembership(None, sid, ctypes.byref(member)):
            return bool(member.value)
    finally:
        ctypes.windll.advapi32.FreeSid(sid)
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
