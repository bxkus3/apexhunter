Markdown

# ApexHunter

Enterprise-grade Endpoint Detection and Response (EDR) threat hunting engine for Windows environments. ApexHunter performs asynchronous, non-disruptive, multi-layered inspection across active system processes and Windows services to identify indicators of compromise (IoCs), Remote Access Trojans (RATs), code injection, and memory anomalies.

## Core Features

- **Asynchronous Orchestration**: Fully decoupled event loop using `asyncio` paired with a high-performance `ThreadPoolExecutor` to handle blocking Win32 API interactions without UI degradation.
- **Native Memory Examination**: Low-level scanning engine leveraging `VirtualQueryEx` and `ReadProcessMemory` to map memory allocation states and detect unmapped code blocks.
- **Authenticode Signature Verification**: Cryptographic trust evaluation utilizing native `wintrust.dll -> WinVerifyTrust` execution via `ctypes`.
- **Heuristic Threat Scoring**: Integrated behavior analysis measuring binary Shannon entropy, import table integrity, PPID spoofing, and parent-child hierarchy deviations.
- **RAT & Beacon Tracking**: Direct correlation between active PIDs and live TCP/UDP network descriptors to spot anomalous outbound persistent polling.
- **Modern UI**: Dark-themed user dashboard constructed via `customtkinter` featuring real-time diagnostic output and process termination controls.

---

## Project Structure

apexhunter/
├── main.py              # Application entry point, environment bootstrap & UAC validation
├── app.py               # CustomTkinter async dashboard interface
├── requirements.txt     # Locked production dependencies
├── .gitignore           # Git version-control asset exclusions
├── README.md            # Technical documentation
├── core/
│   ├── init.py
│   ├── engine.py        # Central scan coordinator, heuristic evaluator & risk matrix
│   ├── signatures.py    # Win32 Authenticode Trust validation layer
│   ├── memory.py        # Memory hollowing detector & RWX page inspection engine
│   └── network.py       # Socket-to-PID correlation & telemetry scanner
└── utils/
├── init.py
└── logger.py        # Rich-based structured diagnostic terminal formatter


---

## Requirements & Dependencies

### System Requirements
- **Operating System**: Windows 10 (20H2 or later), Windows 11, Windows Server 2019, or Windows Server 2022.
- **Privileges**: Administrative privileges (Elevated Token) are mandatory for kernel object handles and memory mapping.
- **Language Runtime**: Python 3.10 or newer (Ensure Python is added to the system `PATH`).

### Required Packages
The application depends on the following external libraries, which must be declared in your `requirements.txt`:

```text
customtkinter>=6.0.0
psutil>=5.9.0
pefile>=2024.8.26
rich>=15.0.0

Installation & Deployment

Execute the following deployment steps inside an elevated command prompt or PowerShell terminal run as Administrator:
1. Environment Setup
PowerShell

# Clone the repository asset tree
git clone [https://github.com/bxkus3/ApexHunter.git](https://github.com/bxkus3/ApexHunter.git)
cd ApexHunter

# Provision an isolated virtual environment
python -m venv venv

# Activate the environment context
.\venv\Scripts\activate

2. Dependency Resolution
PowerShell

# Upgrade core packaging tools
python -m pip install --upgrade pip setuptools wheel

# Install locked production requirements
pip install -r requirements.txt

Operational Usage

Launch the main bootstrap routine directly from the virtual environment context:
PowerShell

python main.py

Privileged Access Escalation

The bootstrap code contains validation routines invoking IsUserAnAdmin(). If executed from an unprivileged context, the application triggers a Windows User Account Control (UAC) prompt via ShellExecuteW with the runas verb to enforce privilege escalation automatically.
Telemetry & Logging Output

    Real-time Interface: Flagged binaries are dynamically color-coded based on risk severity scores:

        CRITICAL / MALICIOUS (Score >= 50): Structural signatures matching structural injection or untrusted root storage executing from volatile directories (AppData, Temp).

        SUSPICIOUS (Score >= 25): Packed binaries with elevated Shannon entropy thresholds or mismatched parent process IDs.

    Local Logs: Scan outcomes are archived inside the root project directory using timestamped JSON payloads and structural markdown sheets (edr_scan_*.json, edr_scan_*.md) for post-incident review.

License

Proprietary / Internal Deployment and Evaluation Only. Unauthorized redistribution or public disclosure of tactical code assets is strictly prohibited.
