import re
from urllib.parse import unquote

# Simple signature-based detection patterns
ATTACK_PATTERNS = {
    "xss": [
        r"(<script.*?>)",
        r"(alert\s*\()",
        r"(onerror\s*=)",
        r"(javascript:)",
        r"(<img\s+src=.*onerror=)"
    ],
    "sql_injection": [
        r"(\s+or\s+)",
        r"(\s+and\s+)",
        r"(union\s+select)",
        r"(information_schema)",
        r"(select\s+.*\s+from)",
        r"(--)",
        r"(%23)"
    ],
    "path_traversal": [
        r"(\.\./)",
        r"(\.\.\\)",
        r"(/etc/passwd)",
        r"(C:\\Windows\\)"
    ],
    "command_injection": [
        r"(;|\||&|\$|\`)", # Command separators
        r"(uname\s+-a)",
        r"(cat\s+)",
        r"(rm\s+-rf)",
        r"(whoami)"
    ]
}

def detect_attack(payload: str) -> str:
    """
    Analyzes a payload string for common attack signatures.
    Returns the attack type if detected, otherwise "none".
    """
    if not payload:
        return "none"
    
    # URL decode and lowercase
    payload = unquote(payload).lower()
    
    for attack_type, patterns in ATTACK_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, payload):
                return attack_type
    
    return "none"
