rule APT_CobaltStrike_Beacon
{
    meta:
        description = "Detects Cobalt Strike Beacon memory configurations and named pipe patterns"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Command and Control"
        technique = "T1071.001"
        confidence = "0.96"
    strings:
        $pipe1 = "\\\\.\\pipe\\msagent_" ascii wide
        $pipe2 = "\\\\.\\pipe\\status_" ascii wide
        $pipe3 = "\\\\.\\pipe\\postex_" ascii wide
        $magic = "%s as %s\\%s: %d" ascii
        $cfg1 = "beacon.x64.dll" ascii
        $cfg2 = "beacon.dll" ascii
        $b64 = "ReflectiveLoader" ascii
        $sleep_mask = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 48 83 EC 30 }
    condition:
        1 of ($pipe*) or 2 of ($cfg*, $magic, $b64) or $sleep_mask
}
