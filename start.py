import subprocess
import sys
import time
import socket
import os
from dotenv import load_dotenv

load_dotenv()

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def start_services():
    local_ip = get_local_ip()
    dash_host = os.getenv("BAITSCOPE_DASHBOARD_HOST") or os.getenv("SENTINEL_DASHBOARD_HOST", "127.0.0.1")
    dash_port = os.getenv("BAITSCOPE_DASHBOARD_PORT") or os.getenv("SENTINEL_DASHBOARD_PORT", "8080")
    
    print("================================================================================")
    print("                                   BAITSCOPE                                    ")
    print("                 Cyber Deception & Threat Intelligence Platform                 ")
    print("                          Deceive. Detect. Investigate.                         ")
    print("================================================================================")

    # Ensure required runtime storage directories exist
    os.makedirs("database", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs(os.path.join("uploads", "quarantine"), exist_ok=True)

    # Generate self-signed SSL certificates if absent on a fresh installation
    if not os.path.exists("cert.pem") or not os.path.exists("key.pem"):
        print("[!] SSL certificates missing. Generating self-signed TLS certs via generate_ssl.py...")
        subprocess.run([sys.executable, "generate_ssl.py"], check=True)
    
    # 1. Start decoy website (binds 0.0.0.0 for public / LAN attraction)
    print("[+] Starting Public Decoy myTunes Website (HTTPS)...")
    decoy_proc = subprocess.Popen([sys.executable, "app_decoy.py"])
    
    # 2. Start admin dashboard (binds 127.0.0.1 for localhost isolation)
    print(f"[+] Starting Secure BAITSCOPE Admin Dashboard on {dash_host}:{dash_port}...")
    dashboard_proc = subprocess.Popen([sys.executable, "app_dashboard.py"])
    
    print("\n[+] Both applications started successfully!")
    print("    [Local Access - This Machine]")
    print("        - Decoy Site (HTTPS):   https://localhost")
    print(f"        - Admin Dashboard:      http://{dash_host}:{dash_port}/admin")
    print(f"\n    [Network Access - Other Devices on Same Wi-Fi/LAN]")
    print(f"        - Decoy Site (HTTPS):   https://{local_ip}")
    if dash_host in ["127.0.0.1", "localhost"]:
        print("        - Admin Dashboard:      [RESTRICTED TO LOCALHOST - ISOLATED FROM LAN]")
    else:
        print(f"        - Admin Dashboard:      http://{dash_host}:{dash_port}/admin")
    print("==========================================================")
    print("Press CTRL+C to stop both applications.")
    
    try:
        while True:
            # Check if any process terminated early
            if decoy_proc.poll() is not None:
                print("[-] Decoy process terminated. Shutting down dashboard...")
                dashboard_proc.terminate()
                break
            if dashboard_proc.poll() is not None:
                print("[-] Dashboard process terminated. Shutting down decoy...")
                decoy_proc.terminate()
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Shutting down services...")
        decoy_proc.terminate()
        dashboard_proc.terminate()
        
        # Wait for processes to exit cleanly
        decoy_proc.wait()
        dashboard_proc.wait()
        print("[+] Both services stopped. Goodbye!")

if __name__ == "__main__":
    start_services()
