rule Ransomware_Extortion_Note
{
    meta:
        description = "Identifies extortion language commonly dropped in ransomware recovery instructions"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Impact"
        technique = "T1486"
        confidence = "0.98"
    strings:
        $str1 = "your files have been encrypted" nocase
        $str2 = "pay the ransom in bitcoin" nocase
        $str3 = "to decrypt your files" nocase
        $str4 = "personal documents, photos, databases" nocase
        $str5 = "tor browser" nocase
    condition:
        2 of them
}
