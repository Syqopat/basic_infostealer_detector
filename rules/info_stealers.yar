rule RedLine_Stealer {
    meta:
        description = "Detects RedLine Info-Stealer payload indicators"
        author = "Basic Info-Stealer Detector"
    strings:
        $s1 = "Select * from Win32_Process" ascii wide
        $s2 = "Autofills" ascii wide
        $s3 = "BrowserLogs" ascii wide
        $s4 = "ColdWallets" ascii wide
        $s5 = "DiscordTokens" ascii wide
    condition:
        3 of ($s*)
}

rule Raccoon_Stealer {
    meta:
        description = "Detects Raccoon Info-Stealer payload indicators"
        author = "Basic Info-Stealer Detector"
    strings:
        $s1 = "sqlite3.dll" ascii wide
        $s2 = "passwords.txt" ascii wide
        $s3 = "cookies.txt" ascii wide
        $s4 = "wallet.dat" ascii wide
    condition:
        3 of ($s*)
}

rule Vidar_Lumma_Stealer {
    meta:
        description = "Detects Vidar or Lumma Info-Stealer payload indicators"
        author = "Basic Info-Stealer Detector"
    strings:
        $s1 = "autofill.txt" ascii wide
        $s2 = "webdata.txt" ascii wide
        $s3 = "telegram_session" ascii wide
        $s4 = "wallet_path" ascii wide
    condition:
        2 of ($s*)
}

rule Generic_Credentials_Token_Stealer {
    meta:
        description = "Detects Generic Credentials and Token Exfiltration Stealers"
        author = "Basic Info-Stealer Detector"
    strings:
        $s1 = "api.telegram.org/bot" ascii wide
        $s2 = "discord.com/api/webhooks" ascii wide
        $s3 = "Login Data" ascii wide
        $s4 = "os_crypt" ascii wide
    condition:
        2 of ($s*)
}
