rule Ransomware_BlackCat_ALPHV
{
    meta:
        description = "Detects BlackCat (ALPHV) Rust-based ransomware binaries"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Impact"
        technique = "T1486"
        confidence = "0.95"
    strings:
        $rust1 = "cargo/registry/src/" ascii
        $rust2 = "alphv" ascii wide nocase
        $note1 = "RECOVER-" ascii wide
        $note2 = "ENTERPRISE LOCKER" ascii wide
        $cmd1 = "wmic shadowcopy delete" ascii wide nocase
        $cmd2 = "iisreset.exe /stop" ascii wide nocase
        $drop1 = "--access-token" ascii
        $drop2 = "--no-prop-servers" ascii
    condition:
        ($rust1 or $rust2) and (1 of ($note*) or 1 of ($cmd*) or 1 of ($drop*))
}
