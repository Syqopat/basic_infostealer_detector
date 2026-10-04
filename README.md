# basic_infostealer_detector

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![YARA Engine](https://img.shields.io/badge/YARA-v4.0-red.svg)](rules/info_stealers.yar)

**basic_infostealer_detector** is a lightweight, low-level Windows endpoint security auditor and YARA rule signature scanner designed to detect info-stealer payloads (RedLine, Raccoon, Vidar, Lumma, Suki, Stealer Bots), Discord client injections, UAC bypass registry hijacks, crypto address clippers, and backdoor sockets.

---

## Technical Overview

- **YARA Signature Engine:** Compiles and matches custom YARA rules (`rules/info_stealers.yar`) against active processes and executables in temporary directories with a fallback pattern matcher.
- **Discord Client Injection Auditor:** Inspects `discord_desktop_core` modules across Discord, Canary, PTB, and Development clients for token stealer JS injections and exfiltration webhooks.
- **UAC Bypass Hijack Detector:** Identifies user-mode UAC elevation bypass hijacks including `ms-settings` (FODHelper/ComputerDefaults), `mscfile` (EventVwr), `CLSID` COM hijacks, and `UserInitMprLogonScript` overrides.
- **C2 Backdoor & Reverse Shell Scanner:** Scans unauthorized listening ports (4444, 5555, 1337, 31337, etc.) and RAT process signatures (AsyncRAT, Remcos, NjRAT, Quasar, Warzone, Venom, XWorm) while filtering legitimate HTTPS and loopback sockets.
- **Zero-False-Positive Whitelist Engine:** Whitelists legitimate games (Roblox, Riot/Valorant, Steam, Minecraft, Epic), media tools (Spotify, Discord), CAD software (SOLIDWORKS), and development environments (VSCode, Antigravity, Ollama, Tailscale).
- **Crypto Clipper & Wallet Auditor:** Detects crypto address swapping hooks and verifies browser extension wallet integrity (MetaMask, Phantom, Coinbase, Trust Wallet).
- **Persistence & Registry Auditor:** Scans `HKCU` and `HKLM` `Run`/`RunOnce` keys, `Winlogon` `Shell`/`Userinit` values, `AppInit_DLLs`, `WMI Event Consumers`, and non-Microsoft scheduled tasks.
- **Automated Remediation Generator:** Produces an administrative `.bat` script to terminate rogue processes, repair injected Discord JS files, remove UAC hijacks, and quarantine bad payloads.

---

## Project Structure

```
basic_infostealer_detector/
│
├── main.py                  # Terminal CLI Entry Point
├── requirements.txt         # Dependencies (rich, psutil, yara-python)
├── README.md                # System Documentation
│
├── rules/                   # YARA Rules Directory
│   └── info_stealers.yar     # Info-Stealer & RAT YARA Signatures
│
├── core/                    # Core Audit Engines
│   ├── __init__.py
│   ├── ps_runner.py          # PowerShell Bridge
│   ├── white_list.py         # Application & Path Whitelist Engine
│   ├── yara_scanner.py       # YARA Rule & Fallback Pattern Scanner
│   ├── discord_injector.py   # Discord Desktop Core Injection Inspector
│   ├── uac_checker.py        # UAC Bypass Registry Auditor
│   ├── backdoor_detector.py  # C2 Socket & RAT Signature Detector
│   ├── clipper_auditor.py    # Crypto Clipper & Address Swap Detector
│   ├── browser_auditor.py    # Browser Extension & WebRequest Engine
│   ├── wallet_auditor.py     # Crypto Wallet Integrity Auditor
│   ├── stealer_defense.py    # Stealer Token Storage Analyzer
│   ├── task_scheduler.py     # Task Scheduler Auditor
│   ├── persistence.py        # Registry, Winlogon & WMI Auditor
│   ├── process_analyzer.py   # Process & Authenticode Verifier
│   ├── directory_inspector.py# ProgramData & Temp Directory Engine
│   ├── network_checker.py    # Socket, Hosts & Proxy Auditor
│   ├── defender_history.py   # Defender Log & QuickScan Engine
│   ├── cleanup_generator.py  # Administrative .bat Script Generator
│   └── report_generator.py   # JSON & Markdown Exporter
│
└── ui/                      # User Interface Module
    ├── __init__.py
    └── terminal.py           # Rich CLI Interface & Tables
```

---

## Installation & Usage

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Syqopat/basic_infostealer_detector.git
   cd basic_infostealer_detector
   ```

2. **Install Dependencies:**
   ```bash
   py -m pip install -r requirements.txt
   ```

3. **Execute:**
   ```bash
   py main.py
   ```

---

## License

Licensed under the MIT License.
