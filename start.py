import subprocess
import sys
import time
import socket

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
    print("==========================================================")
    print("           SENTINEL.X HONEYPOT SERVICE MANAGER            ")
    print("==========================================================")
    
    # 1. Start decoy website
    print("[+] Starting Public Decoy myTunes Website (HTTPS)...")
    decoy_proc = subprocess.Popen([sys.executable, "app_decoy.py"])
    
    # 2. Start admin dashboard
    print("[+] Starting Secure Sentinel.X Admin Dashboard...")
    dashboard_proc = subprocess.Popen([sys.executable, "app_dashboard.py"])
    
    print("\n[+] Both applications started successfully!")
    print("    [Local Access - This Machine]")
    print("        - Decoy Site (HTTPS):   https://localhost")
    print("        - Admin Dashboard:      http://127.0.0.1:8080/admin")
    print(f"\n    [Network Access - Other Devices on Same Wi-Fi/LAN]")
    print(f"        - Decoy Site (HTTPS):   https://{local_ip}")
    print(f"        - Admin Dashboard:      http://{local_ip}:8080/admin")
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
