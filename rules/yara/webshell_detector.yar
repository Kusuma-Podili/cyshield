rule WebShell_Generic_PHP_JSP
{
    meta:
        description = "Detects generic PHP, JSP, or ASPX web shell backdoor components"
        author = "CyberShield Threat Labs"
        severity = "CRITICAL"
        tactic = "Persistence"
        technique = "T1505.003"
        confidence = "0.95"
    strings:
        $php1 = "passthru(" nocase
        $php2 = "shell_exec(" nocase
        $php3 = "system($_GET[" nocase
        $php4 = "eval(base64_decode(" nocase
        $jsp1 = "Runtime.getRuntime().exec(" nocase
        $jsp2 = "ProcessBuilder" nocase
    condition:
        any of them
}
