rule Ransomware_LockBit_3
{
    meta:
        description = "Detects LockBit 3.0 (LockBit Black) ransomware binaries and ransom notes"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Impact"
        technique = "T1486"
        confidence = "0.98"
    strings:
        $s1 = "LockBit 3.0 the world's fastest and most stable ransomware" ascii wide nocase
        $s2 = "restore-my-files.txt" ascii wide
        $s3 = "DECRYPTION ID:" ascii wide
        $s4 = ".lockbit" ascii wide
        $s5 = "vssadmin.exe Delete Shadows /All /Quiet" ascii wide nocase
        $s6 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii wide nocase
        $hex1 = { 48 83 EC 28 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 83 C4 28 C3 }
    condition:
        2 of ($s*) or $hex1
}
