"""
ApexHunter Signature Analyzer
Deep Authenticode validation via native WinVerifyTrust bindings.
"""

import os
import struct
import ctypes
from ctypes import wintypes
from typing import Dict, Any

# WinVerifyTrust GUID: WINTRUST_ACTION_GENERIC_VERIFY_V2
_WVT_GUID_RAW = struct.pack(
    "<IHHBBBBBBBB",
    0x00AAC56B, 0xCD44, 0x11d0,
    0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE
)
WVT_GUID = (ctypes.c_ubyte * 16)(*_WVT_GUID_RAW)

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(ctypes.c_ubyte)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", wintypes.LPVOID),
        ("pSIPClientData", wintypes.LPVOID),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
    ]


class SignatureAnalyzer:
    """
    Cryptographic trust evaluator using WinVerifyTrust.
    Assigns anomaly scores based on certificate validity and file location.
    """

    TRUSTED_ROOT = 0
    INVALID_CERT = 60
    UNSIGNED = 100

    SUSPICIOUS_PATHS = [
        "\\appdata\\", "\\temp\\", "\\tmp\\", "\\programdata\\",
        "\\downloads\\", "\\desktop\\", "\\documents\\",
    ]

    def __init__(self):
        self._wintrust = ctypes.windll.wintrust

    def verify(self, file_path: str) -> Dict[str, Any]:
        """
        Execute WinVerifyTrust against a file path and return structured trust data.
        """
        result = {
            "signed": False,
            "signer": None,
            "status": "unknown",
            "raw_score": 0,
            "location_multiplier": 1.0,
            "final_score": 0
        }

        if not os.path.exists(file_path):
            result["status"] = "file_not_found"
            return result

        file_info = WINTRUST_FILE_INFO()
        file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
        file_info.pcwszFilePath = os.path.abspath(file_path)
        file_info.hFile = None
        file_info.pgKnownSubject = None

        trust_data = WINTRUST_DATA()
        trust_data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        trust_data.pPolicyCallbackData = None
        trust_data.pSIPClientData = None
        trust_data.dwUIChoice = WTD_UI_NONE
        trust_data.fdwRevocationChecks = WTD_REVOKE_NONE
        trust_data.dwUnionChoice = WTD_CHOICE_FILE
        trust_data.pFile = ctypes.pointer(file_info)
        trust_data.dwStateAction = WTD_STATEACTION_VERIFY
        trust_data.hWVTStateData = None
        trust_data.pwszURLReference = None
        trust_data.dwProvFlags = 0
        trust_data.dwUIContext = 0

        try:
            ret = self._wintrust.WinVerifyTrust(
                0, ctypes.byref(WVT_GUID), ctypes.byref(trust_data)
            )
        except OSError as exc:
            result["status"] = f"api_error_{exc.winerror if hasattr(exc, 'winerror') else 'unknown'}"
            return result
        finally:
            trust_data.dwStateAction = WTD_STATEACTION_CLOSE
            try:
                self._wintrust.WinVerifyTrust(
                    0, ctypes.byref(WVT_GUID), ctypes.byref(trust_data)
                )
            except OSError:
                pass

        if ret == 0:
            result["signed"] = True
            result["status"] = "trusted_root"
            result["raw_score"] = self.TRUSTED_ROOT
        elif ret == 0x800B0100:
            result["status"] = "unsigned"
            result["raw_score"] = self.UNSIGNED
        elif ret == 0x800B0101:
            result["signed"] = True
            result["status"] = "expired"
            result["raw_score"] = self.INVALID_CERT
        elif ret == 0x800B010C:
            result["signed"] = True
            result["status"] = "revoked"
            result["raw_score"] = self.INVALID_CERT
        elif ret == 0x80096010:
            result["status"] = "bad_digest"
            result["raw_score"] = self.INVALID_CERT
        elif ret == 0x80092003:
            result["status"] = "file_error"
            result["raw_score"] = self.UNSIGNED
        else:
            result["status"] = f"error_0x{ret:08X}"
            result["raw_score"] = self.INVALID_CERT

        result["location_multiplier"] = self._path_multiplier(file_path)
        result["final_score"] = int(result["raw_score"] * result["location_multiplier"])
        return result

    def _path_multiplier(self, file_path: str) -> float:
        """
        Elevate anomaly score for binaries residing in user-writable directories.
        """
        path_lower = file_path.lower()
        for marker in self.SUSPICIOUS_PATHS:
            if marker in path_lower:
                return 1.5
        return 1.0
