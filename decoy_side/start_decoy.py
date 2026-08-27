import subprocess
import sys
import os

def start_decoy():
    print("==========================================================")
    print("      SENTINEL.X STANDALONE DECOY HONEYPOT NODE          ")
    print("==========================================================")
    
    # 1. Ensure required directories exist
    os.makedirs("database", exist_ok=True)
    os.makedirs("uploads", exist_ok=True)
    
    # 2. Check for SSL certificates, generate if missing
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("[!] SSL certificates missing. Generating self-signed SSL certs...")
        try:
            subprocess.run([sys.executable, "generate_ssl.py"], check=True)
        except Exception as e:
            print(f"[-] Error generating SSL certificates: {e}")
    
    print("[+] Starting Public Decoy Website (HTTPS)...")
    print("[+] Listening on Port 443 (HTTPS) / Fallback Port 8443")
    print("==========================================================")
    
    # 3. Launch app_decoy.py
    try:
        subprocess.run([sys.executable, "app_decoy.py"])
    except KeyboardInterrupt:
        print("\n[-] Decoy node stopped. Goodbye!")

if __name__ == "__main__":
    start_decoy()
