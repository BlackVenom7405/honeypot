"""
BAITSCOPE Advanced Threat Detection Engine (v2.0.0)
Cyber Deception and Threat Intelligence Platform
Deceive. Detect. Investigate.

High-fidelity signature and contextual detection for web attack vectors:
- SQL Injection (Boolean tautologies, UNION-based, comment evasion, time-based, stacked)
- Cross-Site Scripting (XSS) (script tags, event handlers, javascript: URIs, DOM exfiltration)
- Path Traversal (Unix, Windows, URL-encoded, double-encoded, absolute system paths)

Features safe, bounded multi-tier normalization and ReDoS protection.
"""

import re
import html
from urllib.parse import unquote

# Maximum input characters inspected to prevent ReDoS / CPU starvation attacks
MAX_PAYLOAD_LEN = 8192

# =============================================================================
# COMPILED REGEX PATTERNS FOR OPTIMAL HIGH-THROUGHPUT PERFORMANCE
# =============================================================================

# 1. CROSS-SITE SCRIPTING (XSS) PATTERNS
XSS_PATTERNS = [
    # Script tag variants (standard, malformed, slash-separated, uppercase, attributes)
    re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),
    re.compile(r"<\s*script/x\b[^>]*>", re.IGNORECASE),
    
    # HTML tag containing an on* event handler attribute
    re.compile(
        r"<\s*[^>]+?\s+on(?:load|error|click|mouseover|mouseenter|focus|blur|change|submit|toggle|loadstart|pointerdown)\s*=[^>]*>",
        re.IGNORECASE
    ),
    # Attribute breakout event handler injection
    re.compile(
        r"['\"][^'\"]*?\s+on(?:load|error|click|mouseover|focus|blur|toggle)\s*=",
        re.IGNORECASE
    ),
    # JavaScript & pseudoprotocol schemes
    re.compile(
        r"(?:href|src|data|action)\s*=\s*['\"]?\s*(?:javascript|vbscript|data:\s*text/html)\s*:",
        re.IGNORECASE
    ),
    re.compile(
        r"\b(?:javascript|vbscript)\s*:[^\n]*?\(",
        re.IGNORECASE
    ),
    re.compile(
        r"url\s*\(\s*['\"]?\s*javascript\s*:",
        re.IGNORECASE
    ),
    # DOM cookie / storage exfiltration and execution wrappers
    re.compile(
        r"\bdocument\.(?:cookie|location|domain)\b",
        re.IGNORECASE
    ),
    re.compile(
        r"\bwindow\.(?:location|localStorage|sessionStorage)\b\s*=",
        re.IGNORECASE
    ),
    re.compile(
        r"\beval\s*\(\s*(?:atob|unescape|decodeURI|['\"])",
        re.IGNORECASE
    ),
    re.compile(
        r"\bString\.fromCharCode\s*\(",
        re.IGNORECASE
    ),
    # Standalone alert/prompt only within explicit HTML tag / JS syntax context
    re.compile(
        r"<\s*(?:img|svg|body|iframe|input|a)\b[^>]*(?:alert|prompt|confirm)\s*\(",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:alert|prompt|confirm)\s*\(\s*(?:document\.cookie|['\"][^'\"]*['\"]|\d+)\s*\)",
        re.IGNORECASE
    ),
]

# 3. SQL INJECTION (SQLi) PATTERNS
SQLI_PATTERNS = [
    # Boolean tautologies with quotes or numbers: ' OR '1'='1', " OR 1=1
    re.compile(
        r"(['\"][^'\"]*['\"]\s*(?:or|and)\s*['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*['\"])",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:'|\"|\b\d+\b)\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|'[^']*'\s*=\s*'[^']*'|\"[^\"]*\"\s*=\s*\"[^\"]*\"|true\b)",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:'|\"|\d+'|\d+\"|\)\s*['\"]?|['\"]?\s*\))\s*(?:or|and)\s*\(?\s*['\"]?[a-zA-Z0-9_]+['\"]?\s*=\s*['\"]?[a-zA-Z0-9_]+",
        re.IGNORECASE
    ),
    re.compile(
        r"(?:\)|\"|')\s*(?:or|and)\s*\(?\s*(?:'[^']*'|\"[^\"]*\"|\d+)\s*=\s*(?:'[^']*'|\"[^\"]*\"|\d+)\)?",
        re.IGNORECASE
    ),
    re.compile(r"(\badmin' OR '1'='1\b)", re.IGNORECASE),
    
    # Comment-based authentication bypass (requires preceding quote or logic)
    re.compile(r"['\"][^\n]*?(?:--|#|/\*)", re.IGNORECASE),
    
    # UNION-based injections
    re.compile(r"\bunion\s+(?:all\s+)?(?:select|\()", re.IGNORECASE),
    
    # Stacked queries and dangerous DDL/DML
    re.compile(
        r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set|alter\s+table|truncate\s+table)\b",
        re.IGNORECASE
    ),
    re.compile(
        r"\b(?:drop\s+table\s+\w+|insert\s+into\s+\w+\s*values|delete\s+from\s+\w+\s+where)\b",
        re.IGNORECASE
    ),
    
    # Database introspection / Information gathering
    re.compile(r"\binformation_schema\b", re.IGNORECASE),
    re.compile(
        r"\bselect\s+.*\bfrom\s+(?:information_schema|sqlite_master|users|accounts|all_tables|sysobjects)\b",
        re.IGNORECASE
    ),
    re.compile(
        r"\bselect\s+.*?\bfrom\s+\w+\s*(?:where\b|--|#|;|\))",
        re.IGNORECASE
    ),
    
    # Time-based blind injection & heavy computation
    re.compile(
        r"\b(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+|waitfor\s+delay\s+['\"][^'\"]+['\"]|pg_sleep\s*\(\s*\d+\s*\))",
        re.IGNORECASE
    ),
    # Stored procedures & command shell extensions
    re.compile(r"\bexec\s+(?:xp_cmdshell|sp_executesql)\b", re.IGNORECASE),
]

# 4. PATH TRAVERSAL PATTERNS
PATH_TRAVERSAL_PATTERNS = [
    # Relative traversal sequences (Unix, Windows, encoded, mixed)
    re.compile(r"(?:\.\.[/\\]|\.\.%2f|\.\.%5c|%2e%2e[/\\]|%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE),
    re.compile(r"\.\.[/\\]+", re.IGNORECASE),
    re.compile(r"(?:\.[\\/]\.|\.\.)[\\/]", re.IGNORECASE),
    
    # Sensitive system file access (Unix & Windows)
    re.compile(
        r"(?:^|[/\\])(?:etc/(?:passwd|shadow|hosts|group)|proc/self/(?:cmdline|environ)|windows/(?:win\.ini|system\.ini|system32))",
        re.IGNORECASE
    ),
    re.compile(r"\b[A-Za-z]:\\(?:windows|winnt|boot\.ini|system32)\b", re.IGNORECASE),
    re.compile(r"\b(?:boot\.ini|win\.ini)\b", re.IGNORECASE),
    
    # Windows administrative UNC share access
    re.compile(r"\\\\[\w\.\-]+(?:\\[\w\.\-]+)*\\[a-zA-Z]\$", re.IGNORECASE),
    
    # File protocol handler targeting system resources
    re.compile(r"file:\/\/\/(?:etc|windows|sys|proc|[a-zA-Z]:)\b", re.IGNORECASE),
]

# Standard attack categories dictionary in priority evaluation order
ATTACK_CATEGORIES = {
    "XSS": XSS_PATTERNS,
    "SQL Injection": SQLI_PATTERNS,
    "Path Traversal": PATH_TRAVERSAL_PATTERNS
}

# =============================================================================
# NORMALIZATION & CANONICALIZATION FUNCTIONS
# =============================================================================

def normalize_payload(raw: str, max_depth: int = 2, max_len: int = MAX_PAYLOAD_LEN) -> tuple[str, str]:
    """
    Safely and boundedly normalizes input payloads for deep inspection.
    
    Returns:
        (cleaned_decoded_string, sql_canonical_string)
        
    Guarantees:
    - Bounded input length to prevent ReDoS / CPU starvation.
    - Up to 2-pass URL decoding to expose double-encoded evasions.
    - HTML entity decoding (&lt;script&gt; -> <script>).
    - SQL comment stripping (/* ... */ -> space) to defeat SQL keyword obfuscation.
    - Whitespace normalization.
    """
    if not raw or not isinstance(raw, str):
        return "", ""
    
    # 1. Truncate to safe inspection boundary
    bounded = raw[:max_len]
    
    # 2. Bounded URL decoding (maximum 2 iterations)
    current = bounded
    for _ in range(max_depth):
        unquoted = unquote(current)
        if unquoted == current:
            break
        current = unquoted
        
    # 3. HTML entity decoding
    html_decoded = html.unescape(current)
    
    # 4. SQL canonical string: strip C-style comments and normalize spaces
    sql_canonical = re.sub(r'/\*.*?\*/', ' ', html_decoded)
    sql_canonical = sql_canonical.replace('+', ' ')
    sql_canonical = re.sub(r'\s+', ' ', sql_canonical).strip()
    
    return html_decoded, sql_canonical


# =============================================================================
# CORE ATTACK DETECTION INTERFACE
# =============================================================================

def detect_attack(payload: str) -> str:
    """
    Analyzes a payload string for malicious signatures and contextual attack patterns.
    
    Returns standard attack classification:
        'XSS', 'SQL Injection', 'Path Traversal', or 'none'.
    """
    if not payload:
        return "none"
    
    decoded_payload, sql_payload = normalize_payload(payload)
    
    # 1. Priority 1: Cross-Site Scripting (XSS)
    for pattern in XSS_PATTERNS:
        if pattern.search(decoded_payload):
            return "XSS"
            
    # 2. Priority 2: SQL Injection (inspect both decoded and SQL-canonical forms)
    for pattern in SQLI_PATTERNS:
        if pattern.search(decoded_payload) or pattern.search(sql_payload):
            return "SQL Injection"
            
    # 3. Priority 3: Path Traversal
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(decoded_payload):
            return "Path Traversal"
            
    return "none"


def get_attack_details(payload: str) -> dict:
    """
    Provides comprehensive telemetry for logging and forensic evaluation.
    """
    if not payload:
        return {"attack_type": "none", "matched_pattern": None, "severity": "Low"}
        
    decoded_payload, sql_payload = normalize_payload(payload)
    
    for attack_type, patterns in ATTACK_CATEGORIES.items():
        for pattern in patterns:
            target = sql_payload if attack_type == "SQL Injection" and pattern.search(sql_payload) else decoded_payload
            match = pattern.search(target)
            if match:
                severity = "High" if attack_type in ["SQL Injection", "Path Traversal"] else "Medium"
                return {
                    "attack_type": attack_type,
                    "matched_pattern": pattern.pattern,
                    "matched_text": match.group(0),
                    "severity": severity,
                    "normalized_payload": decoded_payload[:256]
                }
                
    return {"attack_type": "none", "matched_pattern": None, "severity": "Low"}
