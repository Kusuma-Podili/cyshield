rule Tool_Mimikatz_Credential_Dumper
{
    meta:
        description = "Detects Mimikatz and derivative credential harvesting tools in memory and disk"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Credential Access"
        technique = "T1003"
        confidence = "0.99"
    strings:
        $mimi1 = "mimikatz" ascii wide nocase
        $mimi2 = "sekurlsa::logonpasswords" ascii wide nocase
        $mimi3 = "lsadump::sam" ascii wide nocase
        $mimi4 = "kerberos::golden" ascii wide nocase
        $mimi5 = "privilege::debug" ascii wide nocase
        $mimi6 = "sekurlsa::wdigest" ascii wide nocase
        $delpy = "gentilkiwi" ascii wide nocase
        $banner = "A La Vie, A L'Amour" ascii wide
    condition:
        2 of ($mimi*) or ($delpy and 1 of ($mimi*)) or $banner
}
