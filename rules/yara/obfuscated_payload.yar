rule Obfuscated_Base64_Executable
{
    meta:
        description = "Detects base64-encoded Windows PE executable headers (TVqQAAMAAAAEAAAA)"
        author = "CyberShield Threat Labs"
        severity = "HIGH"
        tactic = "Defense Evasion"
        technique = "T1027"
        confidence = "0.90"
    strings:
        $b64_pe1 = "TVqQAAMAAAAEAAAA" ascii
        $b64_pe2 = "TVpQAAIAAAAAEAAA" ascii
        $b64_pe3 = "TVoAAAFAAAAEAAAA" ascii
    condition:
        any of them
}
