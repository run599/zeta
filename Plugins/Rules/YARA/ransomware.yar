rule Ransomware_FileEncrypt {
    meta:
        description = "Detects ransomware file encryption patterns"
        author = "ZETA Security"
        severity = "high"
        category = "Ransomware"

    strings:
        $crypto_1 = "AES" nocase wide ascii
        $crypto_2 = "RSA" nocase wide ascii
        $crypto_3 = "ChaCha20" nocase wide ascii
        $crypto_4 = "Twofish" nocase wide ascii
        $crypto_5 = "Serpent" nocase wide ascii
        $file_ext_1 = ".locky" nocase wide ascii
        $file_ext_2 = ".cryptolocker" nocase wide ascii
        $file_ext_3 = ".cryptowall" nocase wide ascii
        $file_ext_4 = ".crypto" nocase wide ascii
        $file_ext_5 = ".xyz" nocase wide ascii
        $file_ext_6 = ".xtbl" nocase wide ascii
        $file_ext_7 = ".zzz" nocase wide ascii
        $file_ext_8 = ".xxx" nocase wide ascii

    condition:
        // P0-5 修复: 原逻辑要求同时含 2 个算法名 + 2 个勒索扩展名，对实际样本过严
        // 改为: 算法名 + 1 个扩展名 (典型勒索软件特征)，或 3 个以上扩展名 (强信号)
        ((2 of ($crypto_*)) and (1 of ($file_ext_*))) or (3 of ($file_ext_*))
}

rule Ransomware_Wiper {
    meta:
        description = "Detects file wiper patterns"
        author = "ZETA Security"
        severity = "high"
        category = "Ransomware"

    strings:
        $wipe_1 = "DeleteFile" nocase wide ascii
        $wipe_2 = "RemoveDirectory" nocase wide ascii
        $wipe_3 = "FormatVolume" nocase wide ascii
        $wipe_4 = "NtDeleteFile" nocase wide ascii
        $wipe_5 = "SHFileOperation" nocase wide ascii
        $path_documents = "\\Documents\\" nocase wide ascii
        $path_pictures = "\\Pictures\\" nocase wide ascii
        $path_videos = "\\Videos\\" nocase wide ascii
        $path_music = "\\Music\\" nocase wide ascii

    condition:
        (3 of ($wipe_*)) and (2 of ($path_*))
}

rule Ransomware_RDP {
    meta:
        description = "Detects ransomware using RDP for spread"
        author = "ZETA Security"
        severity = "high"
        category = "Ransomware"

    strings:
        $rdp_1 = "mstsc.exe" nocase wide ascii
        $rdp_2 = "RemoteDesktopServices" nocase wide ascii
        $rdp_3 = "Terminal Services" nocase wide ascii
        $cred_1 = "CredSSP" nocase wide ascii
        $cred_2 = "GetCredentials" nocase wide ascii
        $cred_3 = "Credential" nocase wide ascii

    condition:
        (2 of ($rdp_*)) and (1 of ($cred_*))
}
