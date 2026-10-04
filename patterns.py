"""A collection of regular expression patterns for identifying cybersecurity certifications and skills in text."""
import re

# certification dictionary
certification_patterns: dict[str, str] = {
    # CompTIA certifications
    "CompTIA Security+": (
        r"(?<!\w)(?:comptia\s*)?security\+(?!\w)"
    ),
    "CompTIA Network+": (
        r"(?<!\w)(?:comptia\s*)?network\+(?!\w)"
    ),
    "CompTIA CySA+": (
        r"(?<!\w)(?:comptia\s*)?cysa\+(?!\w)"
    ),
    "CompTIA PenTest+": (
        r"(?<!\w)(?:comptia\s*)?pentest\+(?!\w)"
    ),
    "CompTIA A+": (
        r"(?<!\w)(?:comptia\s*)?a\+(?!\w)"
    ),
    "CompTIA SecurityX": (
        r"(?<!\w)(?:securityx|casp\+)(?!\w)"
    ),

    # ISC2 and ISACA
    "CISSP": r"(?<!\w)cissp(?!\w)",
    "CISM": r"(?<!\w)cism(?!\w)",
    "CCSP": r"(?<!\w)ccsp(?!\w)",
    "CCSK": r"(?<!\w)ccsk(?!\w)",
    "SSCP": r"(?<!\w)sscp(?!\w)",

    # Ethical hacking and penetration testing
    "CEH": (
        r"(?<!\w)(?:ceh|certified\s+ethical\s+hacker)(?!\w)"
    ),
    "OSCP": (
        r"(?<!\w)oscp(?!\w)|"
        r"offensive\s+security\s+certified\s+professional"
    ),
    "OSWE": r"(?<!\w)oswe(?!\w)",
    "GPEN": r"(?<!\w)gpen(?!\w)",
    "GXPN": r"(?<!\w)gxpn(?!\w)",

    # GIAC
    "GSEC": (
        r"(?<!\w)(?:gsec|giac\s+security\s+essentials)(?!\w)"
    ),
    "GCIH": (
        r"(?<!\w)(?:gcih|giac\s+certified\s+incident\s+handler)(?!\w)"
    ),
    "GCFA": (
        r"(?<!\w)(?:gcfa|giac\s+certified\s+forensic\s+analyst)(?!\w)"
    ),
    "GCFE": (
        r"(?<!\w)(?:gcfe|giac\s+certified\s+forensic\s+examiner)(?!\w)"
    ),
    "GREM": (
        r"(?<!\w)(?:grem|giac\s+reverse\s+engineering\s+malware)(?!\w)"
    ),
    "GNFA": (
        r"(?<!\w)(?:gnfa|giac\s+network\s+forensic\s+analyst)(?!\w)"
    ),
    "GASF": (
        r"(?<!\w)(?:gasf|giac\s+advanced\s+smartphone\s+forensics)(?!\w)"
    ),

    # Microsoft
    "Microsoft SC-200": r"(?<!\w)sc[- ]?200(?!\w)",
    "Microsoft SC-900": r"(?<!\w)sc[- ]?900(?!\w)",
    "Microsoft AZ-900": r"(?<!\w)az[- ]?900(?!\w)",
    "Microsoft AZ-104": r"(?<!\w)az[- ]?104(?!\w)",
    "Microsoft AZ-500": r"(?<!\w)az[- ]?500(?!\w)",

    # AWS, Azure, and Google Cloud
    "AWS Cloud Practitioner": (
        r"\baws\s+(?:certified\s+)?cloud\s+practitioner\b"
    ),
    "AWS Solutions Architect": (
        r"\baws\s+(?:certified\s+)?solutions\s+architect\b"
    ),
    "AWS Security Specialty": (
        r"\baws\s+(?:certified\s+)?security"
        r"(?:\s*-\s*specialty|\s+specialty)?\b"
    ),
    "Azure Security Engineer": (
        r"\bazure\s+(?:security\s+engineer|security\s+certification)\b"
    ),
    "Google Cloud Security Engineer": (
        r"\bgoogle\s+professional\s+cloud\s+security\s+engineer\b"
    ),

    # Other certifications
    "Cisco Certified CyberOps Associate": (
        r"\bcisco\s+certified\s+cyberops\s+associate\b"
    ),
    "EnCE": r"\b(?:ence|encase\s+certified\s+examiner)\b",
    "CFCE": (
        r"\b(?:cfce|certified\s+forensic\s+computer\s+examiner)\b"
    ),
    "CCE": r"\b(?:cce|certified\s+computer\s+examiner)\b",
    "CHFI": r"\bchfi\b",
    "EJPT": r"\bejpt\b",
}


# skills dictionary
skill_patterns: dict[str, str] = {
    # Programming and scripting
    "Python": r"\bpython\b",
    "PowerShell": r"\bpowershell\b",
    "Bash": r"\bbash\b",
    "JavaScript": r"\bjavascript\b",
    "Java": r"(?<!script)\bjava\b",
    "C++": r"\bc\+\+\b",
    "C#": r"\bc#\b",
    "SQL": r"\bsql\b",
    "PHP": r"\bphp\b",
    "Ruby": r"\bruby\b",
    "Perl": r"\bperl\b",
    "Assembly": r"\bassembly\b",
    "Scripting": r"\bscripting\b",

    # Operating systems and platforms
    "Linux": r"\blinux\b",
    "Windows": r"\bwindows\b",
    "macOS": r"\bmacos\b",
    "Kali Linux": r"\bkali(?:\s+linux)?\b",
    "Active Directory": r"\bactive\s+directory\b",
    "AWS": r"\baws\b|amazon web services",
    "Azure": r"\bazure\b",
    "Google Cloud": r"\b(?:gcp|google cloud)\b",

    # SIEM and security platforms
    "SIEM": (
        r"\bsiem\b|security information "
        r"(?:and\s+)?event management"
    ),
    "Splunk": r"\bsplunk\b",
    "Microsoft Sentinel": r"\bmicrosoft sentinel\b",
    "QRadar": r"\bqradar\b",
    "ArcSight": r"\barcsight\b",
    "Elastic Security": r"\belastic(?:\s+security|\s+stack)?\b",
    "Wazuh": r"\bwazuh\b",

    # Endpoint and automation
    "EDR": r"\bedr\b|endpoint detection and response",
    "XDR": r"\bxdr\b|extended detection and response",
    "SOAR": r"\bsoar\b|security orchestration",
    "MFA": r"\bmfa\b|multi[- ]factor authentication",
    "IAM": r"\biam\b|identity and access management",

    # Network and security tools
    "Wireshark": r"\bwireshark\b",
    "tcpdump": r"\btcpdump\b",
    "Zeek": r"\bzeek\b",
    "Suricata": r"\bsuricata\b",
    "Nmap": r"\b(?:nmap|network mapper)\b",
    "Nessus": r"\bnessus\b",
    "Qualys": r"\bqualys\b",
    "Metasploit": r"\bmetasploit\b",
    "Burp Suite": r"\bburp\s+suite\b",
    "SQLmap": r"\bsqlmap\b",
    "MISP": r"\bmisp\b",
    "Velociraptor": r"\bvelociraptor\b",
    "Autopsy": r"\bautopsy\b",
    "FTK": r"\bftk\b",
    "Volatility": r"\bvolatility\b",
    "IDA Pro": r"\bida\s+pro\b",
    "OllyDbg": r"\bollydbg\b",

    # Core cybersecurity skills
    "Network security": r"\bnetwork security\b",
    "Cloud security": r"\bcloud security\b",
    "Application security": r"\bapplication security\b",
    "API security": r"\bapi security\b",
    "Incident response": r"\bincident response\b",
    "Threat intelligence": r"\bthreat intelligence\b",
    "Threat Hunting": r"\bthreat hunting\b",
    "Threat Detection": r"\bthreat detection\b",
    "Digital Forensics": r"\bdigital forensics?\b",
    "Malware Analysis": r"\bmalware analysis\b",
    "Reverse Engineering": r"\breverse engineering\b",
    "Vulnerability Assessment": r"\bvulnerability assessments?\b",
    "Vulnerability Management": r"\bvulnerability management\b",
    "Penetration Testing": r"\bpenetration testing\b",
    "Ethical Hacking": r"\bethical hacking\b",
    "Log Analysis": r"\blog analysis\b",
    "Log Correlation": r"\blog correlation\b",
    "Detection Engineering": r"\bdetection engineering\b",
    "Risk Management": r"\brisk management\b",
    "Security Auditing": r"\bsecurity auditing\b",
    "Compliance": r"\bcompliance\b",
    "Cryptography": r"\bcryptograph(?:y|ic)\b",
    "Encryption": r"\bencryption\b",
    "Digital Evidence": r"\bdigital evidence\b",
    "Memory Forensics": r"\bmemory forensics\b",
    "MITRE ATT&CK": r"\bmitre\s+att&ck\b",

    # Networking
    "TCP/IP": r"\btcp\s*/\s*ip\b",
    "DNS": r"\bdns\b",
    "HTTP/HTTPS": r"\bhttp\s*/\s*https\b",
    "TLS": r"\btls\b",
    "SSH": r"\bssh\b",
    "VPNs": r"\bvpns?\b",
    "Firewalls": r"\bfirewalls?\b",
    "IDS/IPS": (
        r"\bids\s*/\s*ips\b|intrusion detection "
        r"(?:and|/)\s*prevention"
    ),
    "Routing": r"\brouting\b",
    "Switching": r"\bswitching\b",
    "Subnetting": r"\bsubnet(?:ting|s)?\b",
    "Packet Analysis": r"\bpacket analysis\b",
    "Network Traffic Analysis": r"\bnetwork traffic analysis\b",
    "Virtualization": r"\bvirtualization\b",

    # Soft skills
    "Problem Solving": r"\bproblem[- ]solving\b",
    "Critical Thinking": r"\bcritical thinking\b",
    "Analytical Thinking": r"\banalytical thinking\b",
    "Communication": r"\bcommunication skills?\b",
    "Attention to Detail": r"\battention to detail\b",
    "Teamwork": r"\bteamwork\b|ability to work in a team",
}

def extract_matching_terms(
    text: str,
    patterns: dict[str, str],
) -> set[str]:
    """Extracts matching terms from the text based on the provided patterns and returns a set of canonical names."""
    matches: set[str] = set()

    for canonical_name, pattern in patterns.items():
        if re.search(pattern, text, re.IGNORECASE):
            matches.add(canonical_name)

    return matches