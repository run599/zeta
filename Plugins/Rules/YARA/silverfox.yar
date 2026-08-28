rule SilverFox_DriverLoad {
    meta:
        description = "Detects SilverFox BYOVD attack - loads vulnerable drivers"
        author = "ZETA Security"
        severity = "high"
        category = "Exploit"

    strings:
        $driver_1 = "WUDFRd.sys" nocase wide ascii
        $driver_2 = "vmmem.sys" nocase wide ascii
        $driver_3 = "intelppm.sys" nocase wide ascii
        $driver_4 = "iaStorAC.sys" nocase wide ascii
        $load_method_1 = "ZwLoadDriver" nocase wide ascii
        $load_method_2 = "NtLoadDriver" nocase wide ascii
        $load_method_3 = "CreateServiceA" nocase wide ascii
        $load_method_4 = "CreateServiceW" nocase wide ascii
        $driver_path_pattern = "System32\\drivers\\" nocase wide ascii

    condition:
        (2 of ($driver_*)) and (1 of ($load_method_*))
}

rule SilverFox_ProcessInjection {
    meta:
        description = "Detects SilverFox process injection patterns"
        author = "ZETA Security"
        severity = "high"
        category = "Exploit"

    strings:
        $inject_1 = "CreateRemoteThread" nocase wide ascii
        $inject_2 = "WriteProcessMemory" nocase wide ascii
        $inject_3 = "VirtualAllocEx" nocase wide ascii
        $inject_4 = "NtCreateThreadEx" nocase wide ascii
        $target_1 = "svchost.exe" nocase wide ascii
        $target_2 = "lsass.exe" nocase wide ascii
        $target_3 = "winlogon.exe" nocase wide ascii
        $target_4 = "csrss.exe" nocase wide ascii

    condition:
        (3 of ($inject_*)) and (1 of ($target_*))
}

rule SilverFox_RegistryPersistence {
    meta:
        description = "Detects SilverFox registry persistence"
        author = "ZETA Security"
        severity = "high"
        category = "Persistence"

    strings:
        $run_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" nocase wide ascii
        $runonce_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\" nocase wide ascii
        $service_key = "\\System\\CurrentControlSet\\Services\\" nocase wide ascii
        $uninstall_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase wide ascii

    condition:
        // P0-5 修复: $service_key / $uninstall_key 原为死字符串 (定义未引用)
        // 现纳入条件 - 均为合法持久化指标
        (1 of ($run_key, $runonce_key, $service_key, $uninstall_key)) and filesize < 1000000
}
