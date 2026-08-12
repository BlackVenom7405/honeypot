import requests
import time
import os
import random

BASE_URL = "http://localhost:8000"

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6 (OSVDB-3174)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "Python-requests/2.31.0",
    "Wfuzz/3.1.0 - The Web Fuzzer"
]

def generate_random_ip():
    """Generates a random, realistic public IPv4 address."""
    first_octet_choices = [
        random.randint(11, 99),
        random.randint(101, 126),
        random.randint(130, 168),
        random.randint(173, 191),
        random.randint(193, 223)
    ]
    first_octet = random.choice(first_octet_choices)
    second_octet = random.randint(1, 254)
    third_octet = random.randint(1, 254)
    fourth_octet = random.randint(1, 254)
    return f"{first_octet}.{second_octet}.{third_octet}.{fourth_octet}"

# Simplified attacks: SQL Injection, XSS, Path Traversal, Brute Force, Web Shell Detection
attacks = [
    {
        "category": "SQL Injection",
        "name": "SQL Injection on Login Form",
        "url": f"{BASE_URL}/login",
        "method": "POST",
        "data": {"username": "admin' OR '1'='1", "password": "password"}
    },
    {
        "category": "XSS",
        "name": "Cross-Site Scripting (XSS) on Contact Portal",
        "url": f"{BASE_URL}/contact",
        "method": "POST",
        "data": {"name": "Auditor", "email": "test@domain.com", "message": "<script>alert('XSS_POC')</script>"}
    },
    {
        "category": "Path Traversal",
        "name": "Path Traversal on File Endpoint",
        "url": f"{BASE_URL}/api/v1/user?file=../../../../etc/passwd",
        "method": "GET"
    },
    {
        "category": "Brute Force",
        "name": "Brute Force Credential Guessing",
        "url": f"{BASE_URL}/login",
        "method": "POST",
        "data": {"username": "admin", "password": "secretPassword123"}
    }
]

def run_simulations():
    print("==========================================================")
    print("      CYBERGUARD HONEYPOT - ATTACK SIMULATOR (5 VECTORS)  ")
    print("==========================================================")
    
    # 1. Run Web Attacks (SQL Injection, XSS, Path Traversal, Brute Force)
    for attack in attacks:
        random_ip = generate_random_ip()
        random_ua = random.choice(USER_AGENTS)
        headers = {
            "X-Forwarded-For": random_ip,
            "X-Real-IP": random_ip,
            "User-Agent": random_ua
        }
        
        print(f"\n[+] Simulating Vector: {attack['category']}")
        print(f"    Scenario:       {attack['name']}")
        print(f"    Source Node IP: {random_ip}")
        print(f"    User-Agent:     {random_ua}")
        
        try:
            if attack["method"] == "POST":
                response = requests.post(attack["url"], data=attack.get("data"), headers=headers, timeout=5)
            else:
                response = requests.get(attack["url"], headers=headers, timeout=5)
            print(f"    Response Code:  {response.status_code}")
        except Exception as e:
            print(f"    Connection Err: {e}")
        time.sleep(0.5)

    # 2. Run Web Shell Detection Attack (Malicious File Upload)
    print("\n[+] Simulating Vector: Web Shell Detection")
    print("    Scenario:       Malicious PHP Web Shell Upload")
    shell_ip = generate_random_ip()
    shell_ua = random.choice(USER_AGENTS)
    headers = {
        "X-Forwarded-For": shell_ip,
        "X-Real-IP": shell_ip,
        "User-Agent": shell_ua
    }
    print(f"    Source Node IP: {shell_ip}")
    print(f"    User-Agent:     {shell_ua}")

    file_content = b"<?php system($_GET['cmd']); ?>"
    with open("tmp_shell.php", "wb") as f:
        f.write(file_content)
    
    try:
        with open('tmp_shell.php', 'rb') as f:
            files = {'file': ('shell.php', f, 'application/x-php')}
            response = requests.post(f"{BASE_URL}/upload", files=files, headers=headers, timeout=5)
        print(f"    Response Code:  {response.status_code}")
        print(f"    Quarantine Msg: {response.json().get('message')}")
    except Exception as e:
        print(f"    Connection Err: {e}")
    finally:
        if os.path.exists("tmp_shell.php"):
            os.remove("tmp_shell.php")

    print("\n==========================================================")
    print("[+] Simulation complete! View the live multi-node logs at:")
    print("    http://localhost:8000/admin")
    print("==========================================================")

if __name__ == "__main__":
    run_simulations()