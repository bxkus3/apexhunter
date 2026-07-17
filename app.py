#!/usr/bin/env python3
"""
ApexHunter GUI
Modern dark-themed cyber security dashboard using CustomTkinter.
Integrates asyncio background loop with thread-safe Tkinter updates.
"""

import os
import sys
import json
import threading
import asyncio
import queue
import ctypes
from ctypes import wintypes
from typing import Optional, List, Dict, Any
from dataclasses import asdict

try:
    import customtkinter as ctk
except ImportError:
    print("[-] customtkinter is required. Install: pip install customtkinter")
    sys.exit(1)

from core.engine import ScanEngine, ScanResult


class ApexHunterGUI(ctk.CTk):
    """
    Primary application window. Dark theme, high-density data presentation.
    """

    SEVERITY_ORDER = {"CRITICAL": 0, "MALICIOUS": 1, "SUSPICIOUS": 2, "SAFE": 3}

    def __init__(self):
        super().__init__()

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        self.title("ApexHunter | Enterprise EDR")
        self.geometry("1500x950")
        self.minsize(1300, 750)

        self.engine = ScanEngine(max_workers=16)
        self.scan_results: List[ScanResult] = []
        self.service_results: List[Dict[str, Any]] = []
        self._scanning = False
        self._result_queue: queue.Queue = queue.Queue()
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_thread: Optional[threading.Thread] = None

        self._build_header()
        self._build_controls()
        self._build_results_table()
        self._build_status_bar()

        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._start_async_loop()
        self._poll_queue()

    def _start_async_loop(self):
        """
        Launch a dedicated background thread running an asyncio event loop.
        """
        self._async_loop = asyncio.new_event_loop()

        def run_loop():
            asyncio.set_event_loop(self._async_loop)
            self._async_loop.run_forever()

        self._async_thread = threading.Thread(target=run_loop, daemon=True)
        self._async_thread.start()

    def _build_header(self):
        self.header = ctk.CTkFrame(self, height=90)
        self.header.pack(fill="x", padx=12, pady=(12, 6))
        self.header.pack_propagate(False)

        ctk.CTkLabel(
            self.header, text="APEXHUNTER", font=("Consolas", 32, "bold")
        ).pack(side="left", padx=24, pady=12)

        self.score_frame = ctk.CTkFrame(self.header)
        self.score_frame.pack(side="right", padx=24, pady=12)

        self.score_label = ctk.CTkLabel(
            self.score_frame, text="System Score: --", font=("Consolas", 18)
        )
        self.score_label.pack(side="left", padx=14)

        self.proc_count_label = ctk.CTkLabel(
            self.score_frame, text="Processes: --", font=("Consolas", 14)
        )
        self.proc_count_label.pack(side="left", padx=14)

        self.svc_count_label = ctk.CTkLabel(
            self.score_frame, text="Services: --", font=("Consolas", 14)
        )
        self.svc_count_label.pack(side="left", padx=14)

    def _build_controls(self):
        self.controls = ctk.CTkFrame(self, height=55)
        self.controls.pack(fill="x", padx=12, pady=6)
        self.controls.pack_propagate(False)

        self.scan_btn = ctk.CTkButton(
            self.controls, text="START SYSTEM SCAN", command=self._on_scan,
            font=("Consolas", 14, "bold"), width=220, height=36
        )
        self.scan_btn.pack(side="left", padx=24, pady=8)

        self.progress = ctk.CTkProgressBar(self.controls, width=500, height=16)
        self.progress.pack(side="left", padx=24, pady=8)
        self.progress.set(0)

        self.progress_label = ctk.CTkLabel(
            self.controls, text="Idle", font=("Consolas", 12)
        )
        self.progress_label.pack(side="left", padx=10)

    def _build_results_table(self):
        self.table_container = ctk.CTkFrame(self)
        self.table_container.pack(fill="both", expand=True, padx=12, pady=6)

        headers = [
            ("PID", 100, 0), ("Name", 220, 1), ("Risk Score", 110, 2),
            ("Severity", 110, 3), ("Detection", 280, 4),
            ("Signature", 130, 5), ("Actions", 240, 6)
        ]

        self.sort_buttons: List[ctk.CTkButton] = []
        for col, (text, width, sort_idx) in enumerate(headers):
            btn = ctk.CTkButton(
                self.table_container, text=text, width=width, height=30,
                font=("Consolas", 11, "bold"),
                command=lambda idx=sort_idx: self._sort_table(idx)
            )
            btn.grid(row=0, column=col, padx=1, pady=1, sticky="nw")
            self.sort_buttons.append(btn)

        self.scroll_frame = ctk.CTkScrollableFrame(self.table_container)
        self.scroll_frame.grid(
            row=1, column=0, columnspan=len(headers),
            sticky="nsew", padx=2, pady=2
        )
        self.table_container.grid_rowconfigure(1, weight=1)
        for i in range(len(headers)):
            self.table_container.grid_columnconfigure(i, weight=0)

        self.table_rows: List[List[Any]] = []
        self._sort_column = 2
        self._sort_reverse = True

    def _build_status_bar(self):
        self.status = ctk.CTkFrame(self, height=32)
        self.status.pack(fill="x", side="bottom", padx=12, pady=(6, 12))
        self.status.pack_propagate(False)

        self.status_label = ctk.CTkLabel(
            self.status, text="Ready", font=("Consolas", 11)
        )
        self.status_label.pack(side="left", padx=12, pady=4)

    def _on_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.scan_btn.configure(state="disabled", text="SCANNING...")
        self.progress.set(0)
        self.status_label.configure(text="Initializing scan engine...")
        self.scan_results.clear()
        self.service_results.clear()
        self._clear_table_rows()

        future = asyncio.run_coroutine_threadsafe(self._execute_scan(), self._async_loop)
        future.add_done_callback(lambda f: self._result_queue.put(("scan_complete", None)))

    async def _execute_scan(self):
        def progress_cb(done, total):
            self._result_queue.put(("progress", (done, total)))

        self.scan_results = await self.engine.scan_all_processes(
            progress_callback=progress_cb
        )
        self.service_results = await self.engine.scan_services()
        self._result_queue.put(("services_done", len(self.service_results)))

    def _poll_queue(self):
        try:
            while True:
                msg_type, data = self._result_queue.get_nowait()

                if msg_type == "progress":
                    done, total = data
                    if total > 0:
                        self.progress.set(done / total)
                        self.progress_label.configure(text=f"{done}/{total}")

                elif msg_type == "services_done":
                    self.svc_count_label.configure(text=f"Services: {data}")

                elif msg_type == "scan_complete":
                    self._finalize_scan()

                elif msg_type == "error":
                    self.status_label.configure(text=f"Error: {data}")
                    self._scanning = False
                    self.scan_btn.configure(state="normal", text="START SYSTEM SCAN")
        except queue.Empty:
            pass

        self.after(100, self._poll_queue)

    def _finalize_scan(self):
        self._scanning = False
        self.scan_btn.configure(state="normal", text="START SYSTEM SCAN")
        self.progress.set(1.0)

        total = len(self.scan_results)
        critical = len([r for r in self.scan_results if r.severity == "CRITICAL"])
        malicious = len([r for r in self.scan_results if r.severity == "MALICIOUS"])
        suspicious = len([r for r in self.scan_results if r.severity == "SUSPICIOUS"])

        if total == 0:
            sys_score = 100
        else:
            threat_weight = (critical * 100 + malicious * 70 + suspicious * 40) / total
            sys_score = max(0, int(100 - threat_weight))

        self.score_label.configure(text=f"System Score: {sys_score}")
        self.proc_count_label.configure(text=f"Processes: {total}")
        self.status_label.configure(
            text=f"Scan complete. Critical:{critical} Malicious:{malicious} Suspicious:{suspicious}"
        )

        self._sort_table(self._sort_column)

    def _sort_table(self, col: int):
        if self._sort_column == col:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column = col
            self._sort_reverse = True if col == 2 else False

        def sort_key(r: ScanResult):
            if col == 0:
                return r.pid
            elif col == 1:
                return r.name.lower()
            elif col == 2:
                return r.score
            elif col == 3:
                return self.SEVERITY_ORDER.get(r.severity, 99)
            elif col == 4:
                detections = []
                if r.masquerading: detections.append("Masquerading")
                if r.process_hollowing: detections.append("Hollowing")
                if r.rwx_regions: detections.append("RWX")
                if r.ppid_anomaly: detections.append("PPID")
                if r.is_packed: detections.append("Packed")
                if not r.signature.get("signed"): detections.append("Unsigned")
                if r.network_anomalies: detections.append("Network")
                return ",".join(detections).lower()
            elif col == 5:
                return r.signature.get("status", "").lower()
            return 0

        self.scan_results.sort(key=sort_key, reverse=self._sort_reverse)
        self._render_table()

    def _render_table(self):
        self._clear_table_rows()

        for result in self.scan_results:
            if result.severity == "SAFE":
                continue

            row_idx = len(self.table_rows) + 1

            color_map = {
                "CRITICAL": "#FF3333",
                "MALICIOUS": "#FF8800",
                "SUSPICIOUS": "#FFCC00",
                "SAFE": "#33FF33"
            }
            sev_color = color_map.get(result.severity, "#FFFFFF")

            cells = []

            pid_lbl = ctk.CTkLabel(
                self.scroll_frame, text=str(result.pid),
                font=("Consolas", 11), width=100
            )
            pid_lbl.grid(row=row_idx, column=0, padx=2, pady=1, sticky="w")
            cells.append(pid_lbl)

            name_lbl = ctk.CTkLabel(
                self.scroll_frame, text=result.name,
                font=("Consolas", 11), width=220
            )
            name_lbl.grid(row=row_idx, column=1, padx=2, pady=1, sticky="w")
            cells.append(name_lbl)

            score_lbl = ctk.CTkLabel(
                self.scroll_frame, text=str(result.score),
                font=("Consolas", 11, "bold"), width=110
            )
            score_lbl.grid(row=row_idx, column=2, padx=2, pady=1, sticky="w")
            cells.append(score_lbl)

            sev_lbl = ctk.CTkLabel(
                self.scroll_frame, text=result.severity,
                font=("Consolas", 11, "bold"),
                text_color=sev_color, width=110
            )
            sev_lbl.grid(row=row_idx, column=3, padx=2, pady=1, sticky="w")
            cells.append(sev_lbl)

            detections = []
            if result.masquerading:
                detections.append("Masquerading")
            if result.process_hollowing:
                detections.append("Hollowing")
            if result.rwx_regions:
                detections.append(f"RWX:{len(result.rwx_regions)}")
            if result.ppid_anomaly:
                detections.append("PPID")
            if result.is_packed:
                detections.append("Packed")
            if not result.signature.get("signed"):
                detections.append("Unsigned")
            if result.network_anomalies:
                detections.append("Network")

            det_lbl = ctk.CTkLabel(
                self.scroll_frame, text=", ".join(detections[:4]),
                font=("Consolas", 10), width=280
            )
            det_lbl.grid(row=row_idx, column=4, padx=2, pady=1, sticky="w")
            cells.append(det_lbl)

            sig_lbl = ctk.CTkLabel(
                self.scroll_frame,
                text=result.signature.get("status", "unknown"),
                font=("Consolas", 10), width=130
            )
            sig_lbl.grid(row=row_idx, column=5, padx=2, pady=1, sticky="w")
            cells.append(sig_lbl)

            action_frame = ctk.CTkFrame(self.scroll_frame, fg_color="transparent")
            action_frame.grid(row=row_idx, column=6, padx=2, pady=1, sticky="w")

            term_btn = ctk.CTkButton(
                action_frame, text="Kill", width=70, height=26,
                font=("Consolas", 10),
                command=lambda pid=result.pid: self._terminate_process(pid)
            )
            term_btn.pack(side="left", padx=3)

            detail_btn = ctk.CTkButton(
                action_frame, text="Details", width=80, height=26,
                font=("Consolas", 10),
                command=lambda r=result: self._show_details(r)
            )
            detail_btn.pack(side="left", padx=3)

            cells.append(action_frame)
            self.table_rows.append(cells)

    def _clear_table_rows(self):
        for row in self.table_rows:
            for widget in row:
                widget.destroy()
        self.table_rows.clear()

    def _terminate_process(self, pid: int):
        try:
            h_process = ctypes.windll.kernel32.OpenProcess(0x0001, False, pid)
            if h_process:
                ctypes.windll.kernel32.TerminateProcess(h_process, 1)
                ctypes.windll.kernel32.CloseHandle(h_process)
                self.status_label.configure(text=f"Terminated PID {pid}")
            else:
                err = ctypes.windll.kernel32.GetLastError()
                self.status_label.configure(
                    text=f"Failed to terminate PID {pid} (Error: {err})"
                )
        except Exception as exc:
            self.status_label.configure(text=f"Termination error: {exc}")

    def _show_details(self, result: ScanResult):
        detail_win = ctk.CTkToplevel(self)
        detail_win.title(f"Details - {result.name} (PID {result.pid})")
        detail_win.geometry("900x700")

        textbox = ctk.CTkTextbox(detail_win, wrap="word", font=("Consolas", 11))
        textbox.pack(fill="both", expand=True, padx=12, pady=12)

        payload = asdict(result)
        textbox.insert("0.0", json.dumps(payload, indent=2, default=str))
        textbox.configure(state="disabled")

    def _on_close(self):
        self.engine.shutdown()
        if self._async_loop:
            self._async_loop.call_soon_threadsafe(self._async_loop.stop)
        self.destroy()

    def run(self):
        self.mainloop()
        if self._async_thread and self._async_thread.is_alive():
            self._async_thread.join(timeout=3)
