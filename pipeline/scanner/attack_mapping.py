"""
CWE -> MITRE ATT&CK technique mapping.

Sentinel Pipeline (SAST/DAST/secrets) and Sentinel Range (live attack simulation)
are two halves of the same purple-team story: the pipeline finds a class of
vulnerability in code/config *before* release, the Range shows what actually
exploiting that same vulnerability class -- and detecting it -- looks like at
runtime. Tagging every pipeline finding with the ATT&CK technique it maps to
means both tools report in the same language, so a finding here and a live
detection over in range/ can be cross-referenced on one coverage matrix
instead of living in two unrelated dashboards.

Mapping is intentionally conservative: only techniques with a clear,
well-established CWE correspondence are included. Unmapped CWEs return None
rather than a guessed technique.
"""

CWE_TO_ATTACK = {
    "CWE-89":   ("T1190", "Exploit Public-Facing Application"),   # SQL injection
    "CWE-79":   ("T1189", "Drive-by Compromise (stored/reflected XSS)"),
    "CWE-95":   ("T1190", "Exploit Public-Facing Application"),   # eval/code injection
    "CWE-78":   ("T1059", "Command and Scripting Interpreter"),   # os.system / command injection
    "CWE-502":  ("T1190", "Exploit Public-Facing Application"),   # insecure deserialization
    "CWE-327":  ("T1552", "Unsecured Credentials (weak crypto)"),
    "CWE-489":  ("T1600", "Weaken Encryption / Debug Exposure"),
    "CWE-798":  ("T1552.001", "Unsecured Credentials: Credentials In Files"),
    "CWE-321":  ("T1552.004", "Unsecured Credentials: Private Keys"),
    "CWE-639":  ("T1078",     "Valid Accounts (IDOR / broken access control)"),
    "CWE-347":  ("T1550.001", "Use Alternate Authentication Material: Forged Tokens"),
    "CWE-22":   ("T1083",     "File and Directory Discovery (path traversal)"),
    "CWE-319":  ("T1040",     "Network Sniffing (cleartext transmission)"),
    "CWE-209":  ("T1592",     "Gather Victim Org Info (verbose errors)"),
    "CWE-1321": ("T1195",     "Supply Chain Compromise (vulnerable dependency)"),
    "CWE-918":  ("T1210",     "Exploitation of Remote Services (SSRF)"),
    "CWE-1004": ("T1539",     "Steal Web Session Cookie"),
    "CWE-307":  ("T1110",     "Brute Force"),
    "CWE-943":  ("T1190",     "Exploit Public-Facing Application"),  # NoSQL injection
    "CWE-601":  ("T1566.002", "Phishing: Spearphishing Link (open redirect)"),
    "CWE-1035": ("T1195",     "Supply Chain Compromise (vulnerable dependency)"),
    "CWE-693":  ("T1190",     "Exploit Public-Facing Application (missing protection)"),
    "CWE-1021": ("T1185",     "Browser Session Hijacking (clickjacking)"),
    "CWE-200":  ("T1592",     "Gather Victim Org Info (info disclosure)"),
    "CWE-614":  ("T1539",     "Steal Web Session Cookie"),
}


def attack_id_for(cwe):
    """Return the ATT&CK technique ID for a CWE, or '' if unmapped."""
    entry = CWE_TO_ATTACK.get(cwe)
    return entry[0] if entry else ""


def attack_label_for(cwe):
    """Return 'T1190 - Exploit Public-Facing Application' or '' if unmapped."""
    entry = CWE_TO_ATTACK.get(cwe)
    return f"{entry[0]} — {entry[1]}" if entry else ""
