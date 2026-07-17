"""
ApexHunter Memory Analyzer
Process hollowing detection, RWX page hunting, and PPID anomaly verification.
"""

import os
import sys
import struct
import ctypes
from ctypes import wintypes
from typing import Dict, List, Optional, Tuple, Any

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PAGE_EXECUTE_READWRITE = 0x40
MEM_COMMIT = 0x1000


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", wintypes.LPVOID),
        ("PebBaseAddress", wintypes.LPVOID),
        ("Reserved2", wintypes.LPVOID * 2),
        ("UniqueProcessId", ctypes.c_void_p),
        ("Reserved3", wintypes.LPVOID),
    ]


# Legitimate JIT engines that legitimately allocate RWX pages
JIT_WHITELIST = {
    "chrome.exe", "firefox.exe", "msedge.exe", "opera.exe",
    "brave.exe", "vivaldi.exe", "code.exe", "devenv.exe",
    "pycharm64.exe", "idea64.exe", "webstorm64.exe",
}


class MemoryAnalyzer:
    """
    Native memory inspection engine.
    """

    def __init__(self):
        self._kernel32 = kernel32
        self._ntdll = ntdll

    def _open_process(self, pid: int, access: int) -> Optional[wintypes.HANDLE]:
        h = self._kernel32.OpenProcess(access, False, pid)
        if not h:
            return None
        return h

    def get_remote_image_base(self, pid: int) -> Optional[int]:
        """
        Retrieve the image base address from the target process PEB.
        """
        h_process = self._open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if not h_process:
            return None

        try:
            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = wintypes.ULONG()
            status = self._ntdll.NtQueryInformationProcess(
                h_process, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            if status != 0:
                return None

            if pbi.PebBaseAddress is None or pbi.PebBaseAddress.value == 0:
                return None

            is_64bit = sys.maxsize > 2 ** 32
            image_base_offset = 0x10 if is_64bit else 0x08
            image_base = ctypes.c_void_p()
            bytes_read = ctypes.c_size_t()

            success = self._kernel32.ReadProcessMemory(
                h_process,
                ctypes.c_void_p(pbi.PebBaseAddress.value + image_base_offset),
                ctypes.byref(image_base),
                ctypes.sizeof(image_base),
                ctypes.byref(bytes_read)
            )
            if success and bytes_read.value == ctypes.sizeof(image_base):
                return image_base.value
        finally:
            self._kernel32.CloseHandle(h_process)
        return None

    def is_wow64(self, pid: int) -> bool:
        """
        Determine if a remote process is running under WOW64.
        """
        h_process = self._open_process(pid, PROCESS_QUERY_INFORMATION)
        if not h_process:
            return False
        try:
            wow64 = wintypes.BOOL()
            if self._kernel32.IsWow64Process(h_process, ctypes.byref(wow64)):
                return bool(wow64.value)
        finally:
            self._kernel32.CloseHandle(h_process)
        return False

    def scan_rwx_regions(self, pid: int, proc_name: str) -> List[Dict[str, Any]]:
        """
        Enumerate committed memory regions with PAGE_EXECUTE_READWRITE.
        Skips whitelisted JIT engines.
        """
        regions = []
        if proc_name.lower() in JIT_WHITELIST:
            return regions

        h_process = self._open_process(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
        if not h_process:
            return regions

        try:
            mbi = MEMORY_BASIC_INFORMATION()
            addr = 0
            while True:
                ret = self._kernel32.VirtualQueryEx(
                    h_process, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)
                )
                if ret == 0:
                    break

                if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_EXECUTE_READWRITE:
                    regions.append({
                        "base": hex(mbi.BaseAddress),
                        "size": mbi.RegionSize,
                        "protect": mbi.Protect
                    })

                addr = mbi.BaseAddress + mbi.RegionSize
                if addr > 0x7FFF000000000000:
                    break
        finally:
            self._kernel32.CloseHandle(h_process)

        return regions

    def detect_hollowing(self, pid: int, exe_path: str) -> Tuple[bool, str]:
        """
        Compare PE headers in memory against the on-disk image.
        Mismatches indicate process hollowing or manual mapping.
        """
        if not os.path.exists(exe_path):
            return False, ""

        try:
            if self.is_wow64(pid) != self.is_wow64(os.getpid()):
                return False, ""
        except Exception:
            pass

        remote_base = self.get_remote_image_base(pid)
        if not remote_base:
            return False, ""

        h_process = self._open_process(pid, PROCESS_VM_READ)
        if not h_process:
            return False, ""

        try:
            remote_buf = (ctypes.c_ubyte * 2048)()
            bytes_read = ctypes.c_size_t()

            if not self._kernel32.ReadProcessMemory(
                h_process, ctypes.c_void_p(remote_base),
                ctypes.byref(remote_buf), 2048, ctypes.byref(bytes_read)
            ):
                return False, ""

            with open(exe_path, "rb") as f:
                disk_buf = f.read(2048)

            remote_bytes = bytes(remote_buf)[:bytes_read.value]

            if remote_bytes[:2] != b'MZ':
                return True, "Missing MZ header at remote image base"

            remote_lfanew = struct.unpack_from("<I", remote_bytes, 0x3C)[0]
            disk_lfanew = struct.unpack_from("<I", disk_buf, 0x3C)[0]

            if remote_lfanew != disk_lfanew:
                return True, "PE header offset mismatch between disk and memory"

            compare_end = min(remote_lfanew + 4 + 20 + 128, len(remote_bytes), len(disk_buf))
            if remote_bytes[remote_lfanew:compare_end] != disk_buf[disk_lfanew:compare_end]:
                return True, "PE header mismatch between disk and memory (possible process hollowing)"
        finally:
            self._kernel32.CloseHandle(h_process)

        return False, ""

    def check_ppid_anomaly(self, pid: int, ppid: int, name: str,
                           pid_map: Dict[int, str]) -> Tuple[bool, str]:
        """
        Detect parent-child relationship anomalies.
        """
        if ppid not in pid_map:
            return True, "Parent process absent from active snapshot (orphan or spoofed PPID)"

        parent_name = pid_map.get(ppid, "").lower()
        proc_name = name.lower()

        if proc_name == "lsass.exe" and parent_name != "wininit.exe":
            return True, f"lsass.exe spawned by unexpected parent: {parent_name}"

        if proc_name == "services.exe" and parent_name != "wininit.exe":
            return True, f"services.exe spawned by unexpected parent: {parent_name}"

        if proc_name == "smss.exe" and parent_name not in ("system", "smss.exe"):
            return True, f"smss.exe spawned by unexpected parent: {parent_name}"

        if proc_name == "csrss.exe" and parent_name != "smss.exe":
            return True, f"csrss.exe spawned by unexpected parent: {parent_name}"

        non_interactive = {"services.exe", "svchost.exe", "lsass.exe", "wininit.exe", "smss.exe", "csrss.exe"}
        interactive = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}

        if parent_name in non_interactive and proc_name in interactive:
            return True, f"Non-interactive parent ({parent_name}) spawned interactive shell ({proc_name})"

        return False, ""
