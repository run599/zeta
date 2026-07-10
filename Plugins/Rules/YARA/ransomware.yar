rule Ransomware_FileEncrypt {
    meta:
        description = "Detects ransomware file encryption patterns"
        author = "ZETA Security"
        severity = "high"
        category = "Ransomware"
    
    strings:
        $crypto_1 = "AES"
        $crypto_2 = "RSA"
        $crypto_3 = "ChaCha20"
        $crypto_4 = "Twofish"
        $crypto_5 = "Serpent"
        $file_ext_1 = ".locky"
        $file_ext_2 = ".cryptolocker"
        $file_ext_3 = ".cryptowall"
        $file_ext_4 = ".crypto"
        $file_ext_5 = ".xyz"
        $file_ext_6 = ".xtbl"
        $file_ext_7 = ".zzz"
        $file_ext_8 = ".xxx"
    
    condition:
        (2 of ($crypto_*)) and (2 of ($file_ext_*))
}

rule Ransomware_Wiper {
    meta:
        description = "Detects file wiper patterns"
        author = "ZETA Security"
        severity = "high"
        category = "Ransomware"
    
    strings:
        $wipe_1 = "DeleteFile"
        $wipe_2 = "RemoveDirectory"
        $wipe_3 = "FormatVolume"
        $wipe_4 = "NtDeleteFile"
        $wipe_5 = "SHFileOperation"
        $path_documents = "\\Documents\\"
        $path_pictures = "\\Pictures\\"
        $path_videos = "\\Videos\\"
        $path_music = "\\Music\\"
    
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
        $rdp_1 = "mstsc.exe"
        $rdp_2 = "RemoteDesktopServices"
        $rdp_3 = "Terminal Services"
        $cred_1 = "CredSSP"
        $cred_2 = "GetCredentials"
        $cred_3 = "Credential"
    
    condition:
        (2 of ($rdp_*)) and (1 of ($cred_*))
}