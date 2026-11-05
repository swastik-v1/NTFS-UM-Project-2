# FileSentinel DLP — Secure File Transfer Monitoring System

A Python-based Blue Team security tool designed to monitor filesystem activity in real time, detect unauthorized movement of sensitive or restricted files, verify file integrity via cryptographic hashing (SHA-256), generate policy alerts, and stream security telemetry to a local SPLUNK-style dashboard and **native Windows desktop application**.

---
*In other words, an easy to use and efficient (fun) way to track files if you deal with a lot of them on daily basis.*

---

## 🎯 Objectives & Capabilities

- **Real-Time Filesystem Monitoring:** Tracks `CREATED`, `MODIFIED`, `MOVED`, `DELETED`, and `DOWNLOADED` file events across configured target directories.
- **Unauthorized Movement & Exfiltration Detection:**
  - Maintains strict policy lists of sensitive directories and high-risk file types.
  - Detects suspicious outbound transfer vectors (USB / removable media discovered dynamically via Win32 drive bitmasks, UNC network shares, cloud storage sync folders).
- **Cryptographic File Integrity Verification:**
  - Computes pre- and post-transfer chunked hash digests (SHA-256 / SHA-512 / MD5) using Python's built-in `hashlib`.
  - Backed by an ACID-compliant SQLite baseline hash registry (`data/filesentinel.db`) that persists across system reboots.
  - Flags tampering, corruption, or unexpected content alterations (`INTACT` vs `TAMPERED`).
- **Differential Forensics & Content Tracking:**
  - Generates line-by-line unified text diffs (`+`, `-`) and binary byte deltas for modified files.
  - Visualized directly inside the incident inspection drawer.
- **NTFS Alternate Data Stream (ADS) Forensics:**
  - Inspects `:Zone.Identifier` alternate streams on NTFS drives.
  - Automatically classifies web downloads as `DOWNLOADED` events and extracts origin host URLs and referrer URLs.
- **True DLP Content Inspection Engine:**
  - High-performance regex scanning with algorithmic validation.
  - Identifies confidential data in file contents: PCI-DSS payment cards (with Luhn checksum validation), US Social Security Numbers (SSN), AWS/GCP cloud credentials, RSA private keys, and API tokens.
- **Handle-to-Process Attribution & Lineage:**
  - Direct integration with the **Windows Restart Manager API** (`rstrtmgr.dll`) to identify which process locked or modified a file.
  - Tracks process name, PID, user, command-line arguments, and ancestral process trees (`explorer.exe -> cmd.exe -> script.py`).
- **Composite 0–100 Risk Scoring Matrix:**
  - Dynamic heuristic scoring combining transfer vectors, tampering, DLP sensitivity, and process lineage into `INFO`, `WARNING`, and `CRITICAL` alert levels.
- **One-Click Active Remediation:**
  - Isolated Quarantine Vault (`vault/quarantine/`): strips execute permissions, renames files to `.quarantine`, and provides one-click restoration.
  - Native Windows File Explorer integration, in-app file browser, and one-click process termination.
- **Universal Adaptive Event Storm Suppression:**
  - Token-bucket rate limiter that automatically throttles high-frequency non-sensitive write bursts (> 25 writes in 2 seconds) from games, compilers, and updaters, preventing OS buffer starvation (`ReadDirectoryChangesW`).
  - **Zero-Blindspot Guarantee:** Sensitive documents, secrets, and DLP findings always bypass rate-limiting unconditionally.
- **Scope & Exclusions Management:**
  - Web UI modal with interactive directory tree browser to add/remove monitored folders, configure custom excluded directories, and manage ignored background processes.
- **Native Windows Desktop Application:**
  - Runs inside a dedicated native desktop window (powered by `pywebview`).
  - **System Tray Icon (`pystray`):** Runs continuously in the background near the clock; closing the window minimizes to the tray.
  - **Native Toast Notifications:** Displays Windows slide-in alert notifications for `WARNING` and `CRITICAL` events.
  - Right-click tray menu to open dashboard, pause/resume monitoring, or export audit reports.
- **SPLUNK-Style Local Dashboard with Vertical Chat Reports:**
  - Local Flask web UI (`http://127.0.0.1:5000`) with auto-refreshing telemetry, multi-criteria filtering, timeframe presets (`1h`, `24h`, `7d`, `custom`), and smart token queries (`user:admin ext:pem risk:>70`).
  - **Interactive Incident Chat Drawer:** Clicking any log event row opens a vertical report in chat block form (System alert, Telemetry breakdown, Process lineage, NTFS origin, DLP findings, SHA-256 diff, and SOC blue-team advice).
  - Zero external network dependencies (100% localhost).
- **Standalone `.exe` & Windows `.msi` Installer:**
  - Compiled portable executable `FileSentinel.exe` (run directly with zero Python installation required).
  - Official Windows Installer `FileSentinel-Setup.msi` with desktop/start menu shortcuts and clean uninstallation.

---

## 🏗️ Architecture & Workflow

```
[ Filesystem Event ] (watchdog / ReadDirectoryChangesW)
        │
        ▼
[ Self-Isolation Filter ] ───> Ignore own database, logs, vault, reports, and .git
        │
        ▼
[ Write-Burst Debounce ] ────> Suppress rapid OS buffer flushes within debounce window (0.8s)
        │
        ▼
[ Adaptive Storm Suppressor ]> Auto-throttle non-sensitive bursts (>25 writes/2s)
        │                      (Sensitive files unconditionally bypass throttling)
        ▼
[ Event Classification ] ────> Destination Vector (USB Bitmask / Cloud / UNC Shares)
        │                      NTFS Alternate Data Streams (:Zone.Identifier download origin)
        │                      True DLP Content Inspection (PCI Cards with Luhn, SSN, API Keys)
        │
        ▼
[ Process Attribution ] ─────> Windows Restart Manager (rstrtmgr.dll) + Lineage Tree
        │
        ▼
[ Integrity Hashing ] ───────> SHA-256 chunked hashing & SQLite baseline check (INTACT / TAMPERED)
        │                      Text & binary diff tracking (+ / - snippet)
        │
        ▼
[ Composite Risk Scoring ] ──> 0-100 Heuristic Matrix (INFO: 0-39 | WARNING: 40-69 | CRITICAL: 70-100)
        │
        ├───> [ Structured Logger ] ───> logs/audit.log (JSON Lines) + Console
        ├───> [ Alerter ] ─────────────> logs/alerts.log + Terminal Banner
        ├───> [ Native Toast Notifier ]> Windows Notification Center
        └───> [ Desktop / Web UI ] ────> Native Desktop Window or http://localhost:5000
```

---

## 📁 Project Structure

```
├── config.py                 # Central configuration (policies, thresholds, and defaults)
├── config.json               # Enterprise deployment policy override file
├── db.py                     # SQLite engine (baselines, exclusions, quarantine vault)
├── monitor.py                # Watchdog observer, debouncing & adaptive storm suppressor
├── detector.py               # Exfiltration classification, risk matrix & NTFS ADS extraction
├── dlp_scanner.py            # DLP content inspection (PCI credit cards, SSNs, API tokens)
├── process_tracker.py        # Windows Restart Manager API handle & lineage attribution
├── hasher.py                 # Cryptographic chunked hashing & baseline integrity engine
├── diff_tracker.py           # Unified text diff snippets and binary delta tracker
├── logger.py                 # Structured JSONL audit logging & multi-criteria filtering
├── alerter.py                # Policy violation alerting & native toast dispatcher
├── reporter.py               # Automated audit report generator
├── main.py                   # Central CLI and desktop app launcher
├── app_desktop.py            # Native Windows Desktop App with System Tray & Toasts
├── build_all.ps1             # 1-click automated build pipeline (.exe & .msi)
├── assets/                   # Application icons (icon.png, icon.ico)
├── installer/
│   ├── FileSentinel.wxs      # WiX Toolset Windows Installer definition
│   ├── version_info.txt      # Windows PE version resource metadata
│   └── license.rtf           # EULA license displayed in MSI setup wizard
├── dist/                     # Compiled binaries (FileSentinel.exe, FileSentinel-Setup.msi)
├── dashboard/
│   ├── app.py                # Local Flask server providing REST API endpoints
│   ├── templates/index.html  # SPLUNK-inspired dashboard UI with vertical chat drawer
│   └── static/style.css      # Dark-mode dashboard stylesheet
├── data/                     # SQLite database (filesentinel.db)
├── vault/                    # Quarantine vault storage (vault/quarantine/)
├── logs/                     # Audit & alert logs (audit.log, alerts.log)
├── reports/                  # Generated summary and violation reports
├── tests/                    # Automated test suite (73 unit & integration tests)
└── requirements.txt          # Python dependencies
```

---

## 📦 Standalone Executable & Windows Installer (.msi)

### Running the Standalone Executable
You do **not** need Python installed to run the compiled application:
* Location: `dist\FileSentinel.exe`
* Double-click `FileSentinel.exe` to launch the native desktop application immediately.
* It embeds the dashboard, assets, and watchdog engine into a single portable binary.

### Installing via Windows Installer (.msi)
* Location: `dist\FileSentinel-Setup.msi`
* Double-click `FileSentinel-Setup.msi` to run the standard Windows installation wizard.
* Installs `FileSentinel` to `C:\Program Files\FileSentinel`.
* Automatically creates Desktop and Start Menu shortcuts.
* Can be uninstalled cleanly at any time through Windows **Settings > Apps > Installed apps** or **Control Panel**.

### Building `.exe` and `.msi` from Source
To rebuild both binaries at any time, run the automated PowerShell script:
```powershell
powershell -ExecutionPolicy Bypass -File .\build_all.ps1
```
This script handles dependency verification, PyInstaller frozen bundling, portable WiX Toolset setup, and `.msi` compilation.

---

## 🚀 Python Source Installation & Setup

### Prerequisites
- Python 3.10+ (tested through Python 3.13 on Windows 11)
- Standard pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/swastik-v1/NTFS-UM-Project-2.git
cd NTFS-UM-Project-2

# Install dependencies
pip install -r requirements.txt
```

> **Note:** Cryptographic hashing relies on Python's built-in `hashlib` standard library module, requiring zero third-party downloads or external API access.

---

## 💻 Usage

### 1. Launch the Native Windows Desktop App (Default)
```bash
python main.py
# or
python main.py --desktop
# or
python app_desktop.py
```
* Spawns a dedicated native window with the live SPLUNK-style dashboard.
* Adds a shield icon to the **Windows System Tray** (near the taskbar clock).
* Minimizing or closing the window keeps monitoring active in the background.
* Triggers native **Windows Toast Notifications** whenever a suspicious file event occurs.
* Clicking any log row opens the **Vertical Incident Report Drawer in chat block form**.

### 2. Start Headless Monitoring (Console Only)
```bash
python main.py --monitor
```

### 3. Start Monitoring + Browser Dashboard
```bash
python main.py --monitor --dashboard
# Open http://127.0.0.1:5000 in your browser
```

### 4. Generate Security Audit Report
```bash
python main.py --report
```
Compiles a structured report in the `reports/` directory containing summary metrics, policy violation breakdown, and chronological logs.

### 5. Verify Single File Hash
```bash
python main.py --test-hash "path/to/file.docx"
```

---

## 🛑 How to Stop / Exit the Program

### When Running the Desktop App (`--desktop` or `FileSentinel.exe`):
To exit the application, use any of the following convenient options:
1. **Close the Window (`X`):** Simply click the close button on the desktop window. FileSentinel shuts down all background threads, stops monitoring, and exits cleanly.
2. **Press `Ctrl + C`:** If launched from a PowerShell or Command Prompt terminal, pressing `Ctrl + C` immediately terminates all monitoring and Flask threads.
3. **System Tray Menu:** Right-click the FileSentinel shield icon in the system tray and select **Exit FileSentinel**.

### When Running in Terminal Mode (`--monitor`):
* Press **`Ctrl + C`** in your PowerShell or Command Prompt window. The watchdog observer will flush any remaining logs and shut down gracefully.

### Emergency Force-Stop:
If you need to force-terminate any lingering processes from PowerShell:
```powershell
Stop-Process -Name FileSentinel, python -Force -ErrorAction SilentlyContinue
```

---

## 🧪 Testing

Run the automated test suite (73 unit & integration tests):
```bash
python -m pytest tests -v
```
*(If you've got time...)*

---

## 🛡️ Blue Team Security Techniques Implemented (A bit extra stuff)

- **Data Loss Prevention (DLP):** High-speed regex scanning with Luhn checksum validation for payment cards, SSNs, and cloud secrets.
- **Tamper & Differential Detection:** Computes cryptographic pre/post hashes to verify that transferred files have not been modified or corrupted in transit, accompanied by line-by-line unified diff tracking.
- **Kernel Handle & Process Attribution:** Direct integration with the Windows Restart Manager API (`rstrtmgr.dll`) captures operating system username, executable path, command line, and ancestor process lineage trees.
- **NTFS Alternate Data Stream Analysis:** Inspects `:Zone.Identifier` on downloaded files to identify web origin host URLs and referrer URLs.
- **Active Remediation Vault:** Isolates flagged files into a restricted quarantine vault with one-click restore capabilities.
- **Air-Gapped & Offline Ready:** Built completely self-contained with no external cloud API dependencies.
