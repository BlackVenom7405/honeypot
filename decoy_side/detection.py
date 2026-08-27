import re
from urllib.parse import unquote

# Simplified signature-based detection patterns for core attack types
ATTACK_PATTERNS = {
    "XSS": [
        r"(<script.*?>)",
        r"(</script>)",
        r"(alert\s*\()",
        r"(prompt\s*\()",
        r"(onerror\s*=)",
        r"(onload\s*=)",
        r"(javascript:)",
        r"(<img\s+[^>]*onerror=)",
        r"(document\.cookie)"
    ],
    "SQL Injection": [
        r"(\s+or\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(\s+or\s+['\"][^'\"]+['\"]\s*=\s*['\"][^'\"]+)",
        r"(\s+and\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        r"(union\s+select)",
        r"(union\s+all\s+select)",
        r"(information_schema)",
        r"(select\s+.*\s+from)",
        r"(--)",
        r"(%23)",
        r"(sleep\(\d+\))",
        r"(\badmin' OR '1'='1\b)"
    ],
    "Path Traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(%2e%2e%2f)",
        r"(%2e%2e/)",
        r"(/etc/passwd)",
        r"(/etc/shadow)",
        r"(c:\\windows\\)",
        r"(win\.ini)",
        r"(boot\.ini)"
    ]
}

def detect_attack(payload: str) -> str:
    """
    Analyzes a payload string for signature patterns.
    Returns standard attack classification: 'SQL Injection', 'XSS', 'Path Traversal', or 'none'.
    """
    if not payload:
        return "none"
    
    # URL decode and clean payload for inspection
    decoded_payload = unquote(payload)
    lower_payload = decoded_payload.lower()
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lower_payload, re.IGNORECASE):
                return attack_type
    
    return "none"
