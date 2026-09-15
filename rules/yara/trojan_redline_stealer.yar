rule Trojan_RedLine_Stealer
{
    meta:
        description = "Detects RedLine Stealer .NET memory artifacts, browser vault stealers, and discord token grabbers"
        author = "CyberShield Threat Labs"
        severity = "HIGH"
        tactic = "Credential Access"
        technique = "T1555"
        confidence = "0.95"
    strings:
        $s1 = "Login Data" wide
        $s2 = "Web Data" wide
        $s3 = "Cookies" wide
        $s4 = "SELECT * FROM logins" ascii wide
        $s5 = "User_Data" ascii
        $net1 = "Entity1" ascii
        $net2 = "IRemoteEndpoint" ascii
        $disc = "discord/Local Storage/leveldb" ascii wide
        $tele = "Telegram Desktop\\tdata" ascii wide
    condition:
        4 of ($s*, $net*, $disc, $tele)
}
