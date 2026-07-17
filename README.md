# ApexHunter

Enterprise-grade Endpoint Detection and Response (EDR) engine for Windows.
ApexHunter performs real-time and on-demand threat hunting across active
processes and services, targeting advanced RATs, stealthy Trojans, memory
injectors, and persistent stealers.

## Architecture

- **Async Engine**: `asyncio` event loop with `ThreadPoolExecutor` for blocking Win32 API calls.
- **Native Memory Inspection**: Direct `VirtualQueryEx` and `ReadProcessMemory` scans.
- **Authenticode Validation**: Deep `WinVerifyTrust` binding via `ctypes`.
- **Modern GUI**: Dark-themed `customtkinter` dashboard with real-time telemetry.

## Project Structure

```
apexhunter/
├── main.py              # Entry point & UAC escalation
├── app.py               # CustomTkinter GUI
├── requirements.txt     # Dependencies
├── .gitignore           # Git exclusions
├── README.md            # Documentation
├── core/
│   ├── __init__.py
│   ├── engine.py        # Async scan coordinator
│   ├── signatures.py    # WinVerifyTrust Authenticode
│   ├── memory.py        # Process hollowing & RWX hunter
│   └── network.py       # RAT beacon detection
└── utils/
    ├── __init__.py
    └── logger.py        # Rich structured logging
```

## Installation

```powershell
# Clone the repository
git clone https://github.com/bxkus3/ApexHunter.git
cd ApexHunter

# Create virtual environment
python -m venv venv
.env\Scriptsctivate

# Install dependencies
pip install -r requirements.txt
```

## Usage

Run with Administrator privileges for full memory inspection capabilities:

```powershell
python main.py
```

The application will automatically request UAC elevation if not running as Administrator.


## Compatibility

- Windows 10 (20H2+)
- Windows 11
- Windows Server 2019 / 2022

Requires Python 3.10 or newer.

## License

Proprietary / Internal Use Only
