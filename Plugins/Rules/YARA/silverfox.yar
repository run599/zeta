rule SilverFox_DriverLoad {
    meta:
        description = "Detects SilverFox BYOVD attack - loads vulnerable drivers"
        author = "ZETA Security"
        severity = "high"
        category = "Exploit"
    
    strings:
        $driver_1 = "WUDFRd.sys"
        $driver_2 = "vmmem.sys"
        $driver_3 = "intelppm.sys"
        $driver_4 = "iaStorAC.sys"
        $load_method_1 = "ZwLoadDriver"
        $load_method_2 = "NtLoadDriver"
        $load_method_3 = "CreateServiceA"
        $load_method_4 = "CreateServiceW"
        $driver_path_pattern = "System32\\drivers\\"
    
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
        $inject_1 = "CreateRemoteThread"
        $inject_2 = "WriteProcessMemory"
        $inject_3 = "VirtualAllocEx"
        $inject_4 = "NtCreateThreadEx"
        $target_1 = "svchost.exe"
        $target_2 = "lsass.exe"
        $target_3 = "winlogon.exe"
        $target_4 = "csrss.exe"
    
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
        $run_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\"
        $runonce_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\"
        $service_key = "\\System\\CurrentControlSet\\Services\\"
        $uninstall_key = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"
    
    condition:
        (1 of ($run_key, $runonce_key)) and filesize < 1000000
}