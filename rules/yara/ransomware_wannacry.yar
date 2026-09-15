rule Ransomware_WannaCry_WanaCrypt0r
{
    meta:
        description = "Detects WannaCry (WanaCrypt0r 2.0) ransomware family and killswitch domain"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Impact"
        technique = "T1486"
        confidence = "0.99"
    strings:
        $killswitch = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
        $wanacry = "WanaCrypt0r" ascii wide
        $wncry = ".WNCRY" ascii wide
        $tasksche = "tasksche.exe" ascii wide
        $bitcoin = "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94" ascii
        $msg1 = "Ooops, your files have been encrypted!" ascii wide
    condition:
        $killswitch or 2 of ($wanacry, $wncry, $tasksche, $bitcoin, $msg1)
}
