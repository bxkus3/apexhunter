"""
ApexHunter Network Analyzer
Live connection-to-PID mapping and RAT beacon detection.
"""

import psutil
from typing import Dict, List, Any


class NetworkAnalyzer:
    """
    Telemetry tracker for active network connections.
    """

    STANDARD_PORTS = {80, 443, 8080, 8443, 53, 123, 21, 22, 25, 110, 143, 993, 995, 587}

    LEGIT_LISTENERS = {3389, 5985, 5986, 445, 139, 135, 443, 80, 21, 22, 3306, 5432, 1433, 27017}

    SUSPICIOUS_PATHS = [
        "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
        "\\downloads\\", "\\desktop\\", "\\programdata\\",
    ]

    def get_connections(self, pid: int) -> List[Dict[str, Any]]:
        """
        Retrieve all inet connections for a given PID.
        """
        try:
            proc = psutil.Process(pid)
            conns = proc.connections(kind='inet')
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return []

        results = []
        for conn in conns:
            entry = {
                "status": conn.status,
                "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                "local_port": conn.laddr.port if conn.laddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
            }
            results.append(entry)
        return results

    def detect_beacons(self, pid: int, exe_path: str, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify persistent outbound connections to external IPs on non-standard ports.
        """
        anomalies = []
        path_lower = exe_path.lower()
        is_temp = any(marker in path_lower for marker in self.SUSPICIOUS_PATHS)

        for conn in connections:
            if conn["status"] != psutil.CONN_ESTABLISHED or not conn["remote_addr"]:
                continue

            remote_port = conn.get("remote_port")
            if remote_port and remote_port not in self.STANDARD_PORTS:
                severity = "high" if is_temp else "medium"
                anomalies.append({
                    "type": "outbound_nonstandard",
                    "local": conn["local_addr"],
                    "remote": conn["remote_addr"],
                    "severity": severity,
                    "reason": f"Established connection to non-standard port {remote_port}"
                })
        return anomalies

    def detect_hidden_listeners(self, pid: int, proc_name: str, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Flag background processes with no visible UI that are listening on local ports.
        """
        anomalies = []

        for conn in connections:
            if conn["status"] != psutil.CONN_LISTEN or not conn["local_port"]:
                continue

            port = conn["local_port"]
            if port > 1024 and port not in self.LEGIT_LISTENERS:
                anomalies.append({
                    "type": "suspicious_listener",
                    "port": port,
                    "severity": "medium",
                    "reason": f"Process listening on non-standard local port {port} without visible UI"
                })

        return anomalies
