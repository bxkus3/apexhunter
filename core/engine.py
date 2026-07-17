"""
ApexHunter Scan Engine
Async coordinator for multi-layered heuristic scoring.
"""

import os
import math
import asyncio
import psutil
import pefile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Dict, List, Callable, Any, Optional, Tuple
from dataclasses import dataclass, field, asdict

from .signatures import SignatureAnalyzer
from .memory import MemoryAnalyzer
from .network import NetworkAnalyzer


@dataclass
class ScanResult:
    pid: int
    ppid: int
    name: str
    exe_path: str
    cmdline: str
    owner: str
    start_time: str
    signature: Dict[str, Any] = field(default_factory=dict)
    masquerading: bool = False
    masquerading_reason: str = ""
    double_extension: bool = False
    double_ext_reason: str = ""
    hidden: bool = False
    suspicious_path: bool = False
    suspicious_path_reason: str = ""
    entropy: float = 0.0
    is_packed: bool = False
    suspicious_imports: List[str] = field(default_factory=list)
    rwx_regions: List[Dict[str, Any]] = field(default_factory=list)
    process_hollowing: bool = False
    hollowing_reason: str = ""
    ppid_anomaly: bool = False
    ppid_reason: str = ""
    network_anomalies: List[Dict[str, Any]] = field(default_factory=list)
    score: int = 0
    severity: str = "SAFE"


class ScanEngine:
    """
    Asynchronous threat hunting engine.
    Offloads blocking Win32 calls to a ThreadPoolExecutor.
    """

    SYSTEM_PROCESS_PATHS = {
        "svchost.exe": ["C:\\Windows\\System32\\", "C:\\Windows\\SysWOW64\\"],
        "lsass.exe": [r"C:\Windows\System32\"],
        "services.exe": [r"C:\Windows\System32\"],
        "smss.exe": [r"C:\Windows\System32\"],
        "csrss.exe": [r"C:\Windows\System32\"],
        "wininit.exe": [r"C:\Windows\System32\"],
        "winlogon.exe": [r"C:\Windows\System32\"],
        "explorer.exe": [r"C:\Windows\"],
        "taskhostw.exe": [r"C:\Windows\System32\"],
        "spoolsv.exe": [r"C:\Windows\System32\"],
        "dllhost.exe": [r"C:\Windows\System32\"],
        "taskmgr.exe": [r"C:\Windows\System32\"],
        "regedit.exe": [r"C:\Windows\"],
        "sihost.exe": [r"C:\Windows\System32\"],
        "fontdrvhost.exe": [r"C:\Windows\System32\"],
        "dwm.exe": [r"C:\Windows\System32\"],
    }

    SUSPICIOUS_DIRECTORIES = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\downloads\\", "\\desktop\\", "\\documents\\",
        "\\windows\\temp\\", "\\programdata\\",
    ]

    SUSPICIOUS_APIS = {
        b"VirtualAllocEx", b"WriteProcessMemory", b"CreateRemoteThread",
        b"SetThreadContext", b"NtUnmapViewOfSection", b"VirtualProtectEx",
        b"ReadProcessMemory", b"OpenProcess", b"CreateProcessInternal",
        b"InternetOpen", b"InternetConnect", b"HttpSendRequest",
        b"URLDownloadToFile", b"WinExec", b"ShellExecute",
        b"CryptEncrypt", b"CryptDecrypt", b"EnumProcesses",
        b"SetWindowsHookEx", b"RegisterHotKey", b"GetKeyState",
        b"MapViewOfFile", b"CreateFileMapping", b"NtCreateThreadEx",
    }

    def __init__(self, max_workers: int = 16):
        self.sig_analyzer = SignatureAnalyzer()
        self.mem_analyzer = MemoryAnalyzer()
        self.net_analyzer = NetworkAnalyzer()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self._semaphore = asyncio.Semaphore(max_workers)

    async def _run_in_thread(self, func, *args):
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self.executor, func, *args)

    def _check_masquerading(self, proc_name: str, exe_path: str) -> Tuple[bool, str]:
        name = proc_name.lower()
        if name not in self.SYSTEM_PROCESS_PATHS:
            return False, ""
        path_lower = exe_path.lower()
        for legit in self.SYSTEM_PROCESS_PATHS[name]:
            if path_lower.startswith(legit.lower()):
                return False, ""
        return True, f"Critical system process '{proc_name}' executing from illegitimate path: {exe_path}"

    def _check_double_extension(self, file_path: str) -> Tuple[bool, str]:
        base = os.path.basename(file_path).lower()
        parts = base.split(".")
        if len(parts) >= 3 and parts[-1] == "exe":
            return True, f"Double extension detected: {base}"
        return False, ""

    def _check_suspicious_path(self, exe_path: str) -> Tuple[bool, str]:
        path_lower = exe_path.lower()
        for susp in self.SUSPICIOUS_DIRECTORIES:
            if susp in path_lower:
                return True, f"Binary executing from suspicious directory: {exe_path}"
        return False, ""

    def _is_file_hidden(self, file_path: str) -> bool:
        import ctypes
        from ctypes import wintypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(os.path.abspath(file_path))
        if attrs == 0xFFFFFFFF:
            return False
        return bool(attrs & 0x2)

    def _shannon_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for byte_val in range(256):
            p_x = float(data.count(byte_val)) / length
            if p_x > 0.0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    def _check_pe_heuristics(self, file_path: str) -> Dict[str, Any]:
        result = {"suspicious_imports": [], "entropy": 0.0, "is_packed": False}
        if not os.path.exists(file_path):
            return result

        try:
            with open(file_path, "rb") as f:
                sample = f.read(65536)
            result["entropy"] = self._shannon_entropy(sample)
        except Exception:
            pass

        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories([
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
            ])

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for func in entry.imports:
                        if func.name:
                            for api in self.SUSPICIOUS_APIS:
                                if api in func.name:
                                    result["suspicious_imports"].append(
                                        f"{entry.dll.decode(errors='ignore')}:{func.name.decode(errors='ignore')}"
                                    )
                                    break

            if hasattr(pe, 'sections'):
                packed_sections = 0
                for section in pe.sections:
                    if section.get_entropy() > 7.0:
                        packed_sections += 1
                if packed_sections >= 2 or result["entropy"] > 7.2:
                    result["is_packed"] = True

            pe.close()
        except Exception:
            pass

        if result["entropy"] > 7.2:
            result["is_packed"] = True

        return result

    def _extract_exe_from_command(self, cmd: str) -> Optional[str]:
        cmd = cmd.strip()
        if cmd.startswith('"'):
            end = cmd.find('"', 1)
            if end != -1:
                return cmd[1:end]
        else:
            parts = cmd.split()
            if parts:
                return parts[0]
        return None

    def _calculate_score(self, result: ScanResult) -> None:
        score = 0

        if result.masquerading:
            score += 50
        if result.double_extension:
            score += 30
        if result.hidden:
            score += 10
        if result.suspicious_path:
            score += 15

        sig_status = result.signature.get("status", "")
        if sig_status == "unsigned":
            score += result.signature.get("final_score", 100)
        elif sig_status in ("expired", "revoked", "bad_digest"):
            score += result.signature.get("final_score", 60)

        if result.is_packed:
            score += 15
        if len(result.suspicious_imports) >= 3:
            score += 15
        elif len(result.suspicious_imports) > 0:
            score += 10

        if result.rwx_regions:
            score += 25
        if result.process_hollowing:
            score += 40
        if result.ppid_anomaly:
            score += 15

        for net in result.network_anomalies:
            if net.get("severity") == "high":
                score += 15
            else:
                score += 10

        result.score = min(score, 100)

        if result.score >= 70:
            result.severity = "CRITICAL"
        elif result.score >= 50:
            result.severity = "MALICIOUS"
        elif result.score >= 25:
            result.severity = "SUSPICIOUS"
        else:
            result.severity = "SAFE"

    async def scan_process(self, pid: int, pid_ppid_map: Dict[int, int],
                           pid_name_map: Dict[int, str]) -> Optional[ScanResult]:
        """
        Full heuristic scan of a single process.
        """
        async with self._semaphore:
            try:
                proc = psutil.Process(pid)
                name = proc.name()
                exe = proc.exe()
                cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
                try:
                    owner = proc.username()
                except Exception:
                    owner = "N/A"
                try:
                    start_time = datetime.fromtimestamp(proc.create_time()).isoformat()
                except Exception:
                    start_time = "N/A"
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                return None
            except Exception:
                return None

            sig = await self._run_in_thread(self.sig_analyzer.verify, exe) if os.path.exists(exe) else {"signed": False, "status": "unknown"}

            masq, masq_reason = self._check_masquerading(name, exe)
            dbl_ext, dbl_ext_reason = self._check_double_extension(exe)
            hidden = self._is_file_hidden(exe) if os.path.exists(exe) else False
            susp_path, susp_path_reason = self._check_suspicious_path(exe)
            pe_heur = self._check_pe_heuristics(exe) if os.path.exists(exe) else {"suspicious_imports": [], "entropy": 0.0, "is_packed": False}

            rwx = []
            hollow = False
            hollow_reason = ""
            if os.path.exists(exe):
                rwx = await self._run_in_thread(self.mem_analyzer.scan_rwx_regions, pid, name)
                hollow, hollow_reason = await self._run_in_thread(self.mem_analyzer.detect_hollowing, pid, exe)

            ppid_ano, ppid_reason = self.mem_analyzer.check_ppid_anomaly(pid, proc.ppid(), name, pid_name_map)

            net_anomalies = []
            try:
                conns = self.net_analyzer.get_connections(pid)
                net_anomalies.extend(self.net_analyzer.detect_beacons(pid, exe, conns))
                net_anomalies.extend(self.net_analyzer.detect_hidden_listeners(pid, name, conns))
            except Exception:
                pass

            result = ScanResult(
                pid=pid,
                ppid=proc.ppid(),
                name=name,
                exe_path=exe,
                cmdline=cmdline,
                owner=owner,
                start_time=start_time,
                signature=sig,
                masquerading=masq,
                masquerading_reason=masq_reason,
                double_extension=dbl_ext,
                double_ext_reason=dbl_ext_reason,
                hidden=hidden,
                suspicious_path=susp_path,
                suspicious_path_reason=susp_path_reason,
                entropy=pe_heur["entropy"],
                is_packed=pe_heur["is_packed"],
                suspicious_imports=pe_heur["suspicious_imports"],
                rwx_regions=rwx,
                process_hollowing=hollow,
                hollowing_reason=hollow_reason,
                ppid_anomaly=ppid_ano,
                ppid_reason=ppid_reason,
                network_anomalies=net_anomalies
            )
            self._calculate_score(result)
            return result

    async def scan_all_processes(self, progress_callback: Optional[Callable[[int, int], None]] = None) -> List[ScanResult]:
        """
        Orchestrate a full system process scan.
        """
        pid_ppid_map: Dict[int, int] = {}
        pid_name_map: Dict[int, str] = {}
        active_pids = []

        for p in psutil.process_iter():
            try:
                active_pids.append(p.pid)
                pid_ppid_map[p.pid] = p.ppid()
                pid_name_map[p.pid] = p.name()
            except Exception:
                continue

        total = len(active_pids)
        completed = 0
        results = []

        tasks = []
        for pid in active_pids:
            task = asyncio.create_task(self.scan_process(pid, pid_ppid_map, pid_name_map))
            tasks.append(task)

        for coro in asyncio.as_completed(tasks):
            try:
                res = await coro
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                if res:
                    results.append(res)
            except Exception:
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        return sorted(results, key=lambda x: x.score, reverse=True)

    async def scan_services(self) -> List[Dict[str, Any]]:
        """
        Enumerate Windows services and score their binaries.
        """
        flagged = []
        try:
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    binpath = info.get("binpath", "")
                    if not binpath:
                        continue

                    exe = self._extract_exe_from_command(binpath)
                    if not exe or not os.path.exists(exe):
                        continue

                    sig = await self._run_in_thread(self.sig_analyzer.verify, exe)
                    masq, _ = self._check_masquerading(os.path.basename(exe), exe)
                    pe_heur = self._check_pe_heuristics(exe)

                    score = 0
                    if masq:
                        score += 50
                    if not sig.get("signed"):
                        score += 25
                    if pe_heur["is_packed"]:
                        score += 15
                    if pe_heur["entropy"] > 7.2:
                        score += 10

                    if score >= 20:
                        flagged.append({
                            "name": info.get("name"),
                            "display_name": info.get("display_name"),
                            "binpath": exe,
                            "pid": info.get("pid"),
                            "start_type": info.get("start_type"),
                            "signature": sig,
                            "score": score
                        })
                except Exception:
                    continue
        except Exception:
            pass

        return flagged

    def shutdown(self):
        self.executor.shutdown(wait=True)
