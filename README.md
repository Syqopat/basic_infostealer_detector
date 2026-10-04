# 🛡️ Basic Info-Stealer Detector

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![YARA Support](https://img.shields.io/badge/YARA-Rules%20Engine-red.svg)](#features)

**Basic Info-Stealer Detector** is a specialized Windows security auditor and memory/file YARA scanner designed to detect information stealers (RedLine, Raccoon, Vidar, Lumma, Suki, Stealer Bots), Discord client injections, UAC bypass hijacks, crypto address clippers, and backdoor sockets.

---

## 🚀 Key Features

- **YARA Rule Signature Engine:** Integrates custom YARA rules (`rules/info_stealers.yar`) to scan running memory processes and user directories for known info-stealers (RedLine, Raccoon, Vidar, Lumma, Token Grabbers) with a fast pattern-matching fallback scanner.
- **Discord & Discord Canary Injection Audit:** Inspects `discord_desktop_core` modules across Discord, Discord Canary, Discord PTB, and Discord Development clients for token stealer JavaScript injections, obfuscated `eval()` blocks, and exfiltration webhooks.
- **UAC Bypass Hijack Detector:** Identifies user-mode UAC elevation bypass hijacks including `ms-settings` (FODHelper/ComputerDefaults), `mscfile` (EventVwr), `CLSID` COM hijacks, and `UserInitMprLogonScript` overrides.
- **Backdoor & Reverse Shell Scanner:** Detects unauthorized listening C2 ports (e.g. 4444, 5555, 1337, 31337) and RAT signatures (AsyncRAT, NjRAT, Quasar, Remcos, Warzone, Venom, XWorm) while ignoring legitimate loopback & HTTPS sockets.
- **Zero False Positive Whitelist Engine:** Whitelists legitimate games (Roblox, Riot/Valorant, Steam, Minecraft, Epic), media tools (Spotify, Discord), CAD software (SOLIDWORKS), and development environments (VSCode, Antigravity, Ollama, Tailscale).
- **Crypto Clipper & Wallet Auditor:** Detects crypto address swapping malware hooks and verifies browser extension wallet integrity (MetaMask, Phantom, Coinbase, Trust Wallet).
- **Task Scheduler Persistence Audit:** Filters out native `\Microsoft\` tasks to isolate third-party or rogue scheduled tasks, executable triggers, and periodic repetition mechanics.
- **Auto-Run Registry & Winlogon Inspector:** Audits `HKCU` and `HKLM` `Run`, `RunOnce`, `WOW6432Node`, `Winlogon` `Shell` & `Userinit` hijacks, `AppInit_DLLs`, and `WMI Event Consumers` (`root\subscription`).
- **Active Processes & Code Signature Verification:** Validates Authenticode digital signatures (`Get-AuthenticodeSignature`), isolates unsigned processes running from user directories (`%APPDATA%`, `%TEMP%`, `%PROGRAMDATA%`), and detects DLL side-loading.
- **One-Click Administrative Cleanup Script Generator:** Generates a standalone `.bat` script on your Desktop configured to terminate malicious processes, repair injected Discord JS files, delete UAC bypass hijacks, unregister rogue tasks, and quarantine payloads.
- **Exportable Forensic Reports:** Saves structured threat intelligence reports in JSON and Markdown formats.

---

## 🛠️ Architecture

```
BasicInfoStealerDetector/
│
├── main.py                  # CLI Terminal Entry Point
├── requirements.txt         # Terminal UI & System Dependencies
├── README.md                # System Documentation & Usage Guide
│
├── rules/                   # YARA Signature Rules
│   └── info_stealers.yar     # RedLine, Raccoon, Vidar, Lumma & Stealer Rules
│
├── core/                    # Security Audit Engines
│   ├── __init__.py
│   ├── ps_runner.py          # PowerShell Execution Bridge
│   ├── white_list.py         # Whitelisting & False Positive Engine
│   ├── yara_scanner.py       # YARA Rule & String Pattern Scanner
│   ├── discord_injector.py   # Discord & Canary JS Injection Engine
│   ├── uac_checker.py        # UAC Bypass Registry Hijack Auditor
│   ├── backdoor_detector.py  # C2 Backdoor & RAT Scanner
│   ├── clipper_auditor.py    # Crypto Clipper & Address Swapper Auditor
│   ├── browser_auditor.py    # Browser Extension & WebRequest Engine
│   ├── wallet_auditor.py     # Crypto Wallet Integrity Auditor
│   ├── stealer_defense.py    # Stealer Token Storage Analyzer
│   ├── task_scheduler.py     # Task Scheduler Forensic Engine
│   ├── persistence.py        # Registry, Winlogon & WMI Audit
│   ├── process_analyzer.py   # Process & Authenticode Verifier
│   ├── directory_inspector.py# ProgramData & Temp Directory Engine
│   ├── network_checker.py    # Socket, Hosts & Proxy Auditor
│   ├── defender_history.py   # Defender Threat Log Engine
│   ├── cleanup_generator.py  # One-Click .bat Script Generator
│   └── report_generator.py   # JSON & Markdown Exporter
│
└── ui/                      # Terminal User Interface
    ├── __init__.py
    └── terminal.py           # Rich UI Banners, Tables & Progress Bars
```

---

## 📦 Installation & Quick Start

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Syqopat/AdvencedTrojanDetect.git
   cd AdvencedTrojanDetect
   ```

2. **Install Dependencies:**
   ```bash
   py -m pip install -r requirements.txt
   ```

3. **Run Basic Info-Stealer Detector:**
   ```bash
   py main.py
   ```

---

## 💻 Interactive Terminal Controls (13 Forensic Modules)

| Option | Audit Engine | Target Scope |
| :---: | :--- | :--- |
| **1** | **Full Security Scan** | Executes all 13 forensic modules |
| **2** | **YARA Rule Signature Scan** | Scans processes & files using `info_stealers.yar` |
| **3** | **Discord & Canary Injection Audit** | Inspects `desktop_core` `index.js` files |
| **4** | **UAC Bypass Hijack Audit** | Audits `ms-settings`, `mscfile`, `UserInit` |
| **5** | **Crypto Clipper & Address Swap Scan** | Clipboard hooks & swapper processes |
| **6** | **Browser Extension Security Audit** | Chrome, Edge, Brave, Opera `manifest.json` |
| **7** | **Crypto Wallet Integrity Audit** | Exodus, Atomic, MetaMask, Phantom |
| **8** | **Backdoor & Reverse Shell Scan** | Scans C2 listening ports and RAT signatures |
| **9** | **Task Scheduler Audit** | Scans scheduled tasks outside `\Microsoft\` |
| **10** | **Startup & Registry Keys Audit** | Audits `Run`, `RunOnce`, `Winlogon`, `WMI` |
| **11** | **Active Processes & Signatures** | Verifies Authenticode digital signatures |
| **12** | **Critical Directories Scan** | Scans `ProgramData` and `%TEMP%` executables |
| **13** | **Network Ports & Proxy Hijacks** | Checks sockets, PIDs, `hosts` file & Proxy |
| **14** | **Defender History & QuickScan** | Retrieves threat logs & triggers Defender |
| **15** | **Generate Cleanup Script** | Builds one-click administrative `.bat` script |
| **16** | **Export Audit Reports** | Generates JSON & Markdown reports |
| **0** | **Exit** | Closes Basic Info-Stealer Detector |

---

## 🛡️ License

Licensed under the MIT License.
