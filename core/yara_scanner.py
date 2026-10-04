import os
import sys
import psutil
import re

RULE_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "info_stealers.yar")

def scan_file_with_yara(file_path):
    if not os.path.exists(file_path):
        return []
    
    matches = []
    try:
        import yara
        if os.path.exists(RULE_FILE):
            rules = yara.compile(RULE_FILE)
            yara_matches = rules.match(file_path)
            for m in yara_matches:
                matches.append(m.rule)
            return matches
    except Exception:
        pass
    
    try:
        with open(file_path, "rb") as f:
            data = f.read(5000000)
            
        redline_sigs = [b"Select * from Win32_Process", b"Autofills", b"BrowserLogs", b"ColdWallets", b"DiscordTokens"]
        redline_count = sum(1 for sig in redline_sigs if sig in data)
        if redline_count >= 3:
            matches.append("RedLine_Stealer")

        raccoon_sigs = [b"sqlite3.dll", b"passwords.txt", b"cookies.txt", b"wallet.dat"]
        raccoon_count = sum(1 for sig in raccoon_sigs if sig in data)
        if raccoon_count >= 3:
            matches.append("Raccoon_Stealer")

        vidar_sigs = [b"autofill.txt", b"webdata.txt", b"telegram_session", b"wallet_path"]
        vidar_count = sum(1 for sig in vidar_sigs if sig in data)
        if vidar_count >= 2:
            matches.append("Vidar_Lumma_Stealer")

        stealer_sigs = [b"api.telegram.org/bot", b"discord.com/api/webhooks", b"Login Data", b"os_crypt"]
        stealer_count = sum(1 for sig in stealer_sigs if sig in data)
        if stealer_count >= 2:
            matches.append("Generic_Credentials_Token_Stealer")
    except Exception:
        pass

    return matches

def audit_yara_rules():
    findings = []
    suspicious_dirs = [
        os.getenv("TEMP", ""),
        os.getenv("APPDATA", ""),
        os.getenv("LOCALAPPDATA", ""),
        os.getenv("PROGRAMDATA", "")
    ]
    
    scanned_files = set()
    for d in suspicious_dirs:
        if d and os.path.exists(d):
            for root, _, files in os.walk(d):
                for file in files:
                    if file.lower().endswith((".exe", ".dll", ".tmp", ".scr", ".bat", ".vbs")):
                        full_path = os.path.join(root, file)
                        if full_path not in scanned_files:
                            scanned_files.add(full_path)
                            matched_rules = scan_file_with_yara(full_path)
                            if matched_rules:
                                findings.append({
                                    "FilePath": full_path,
                                    "MatchedRules": ", ".join(matched_rules),
                                    "IsSuspicious": True
                                })
                            if len(scanned_files) > 100:
                                break

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            exe_path = proc.info.get('exe')
            if exe_path and os.path.exists(exe_path) and exe_path not in scanned_files:
                scanned_files.add(exe_path)
                matched_rules = scan_file_with_yara(exe_path)
                if matched_rules:
                    findings.append({
                        "FilePath": f"PID: {proc.info['pid']} ({proc.info['name']}) -> {exe_path}",
                        "MatchedRules": ", ".join(matched_rules),
                        "IsSuspicious": True
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return findings
