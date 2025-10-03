import requests
import ssl, socket
import datetime
import subprocess
import time
import logging
import os
import hashlib

# =======================
# KONFIGURASI
# =======================
DOMAIN = "rupiahid-dompet.my.id"
CHECK_INTERVAL = 3600  # detik
LOG_FILE = "domain_monitor.log"
BACKUP_DIR = "/path/to/backup_dir"  # sesuaikan lokasi backup
WEB_ROOT = "/var/www/html"  # folder utama domain

# =======================
# SETUP LOGGING
# =======================
logging.basicConfig(filename=LOG_FILE,
                    level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# =======================
# FUNGSI MONITOR SSL
# =======================
def check_ssl(domain):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(10)
            s.connect((domain, 443))
            cert = s.getpeercert()
            expire = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
            days_left = (expire - datetime.datetime.utcnow()).days
            return days_left
    except Exception as e:
        logging.error(f"SSL check error: {e}")
        return None

# =======================
# FUNGSI MONITOR HTTP
# =======================
def check_http(domain):
    try:
        r = requests.get("https://" + domain, timeout=10)
        return r.status_code
    except Exception as e:
        logging.error(f"HTTP check error: {e}")
        return None

# =======================
# FUNGSI BACKUP FILE DOMAIN
# =======================
def backup_files():
    try:
        for root, dirs, files in os.walk(WEB_ROOT):
            for file in files:
                path = os.path.join(root, file)
                rel_path = os.path.relpath(path, WEB_ROOT)
                backup_path = os.path.join(BACKUP_DIR, rel_path)
                os.makedirs(os.path.dirname(backup_path), exist_ok=True)
                with open(path, "rb") as f_src, open(backup_path, "wb") as f_dst:
                    f_dst.write(f_src.read())
        logging.info("Backup file domain selesai.")
    except Exception as e:
        logging.error(f"Backup error: {e}")

# =======================
# FUNGSI CEK INTEGRITAS FILE
# =======================
file_hashes = {}

def scan_integrity():
    global file_hashes
    tampered = False
    for root, dirs, files in os.walk(WEB_ROOT):
        for file in files:
            path = os.path.join(root, file)
            with open(path, "rb") as f:
                data = f.read()
                h = hashlib.sha256(data).hexdigest()
                if path in file_hashes:
                    if file_hashes[path] != h:
                        logging.warning(f"⚠️ File diubah: {path}")
                        tampered = True
                file_hashes[path] = h
    return tampered

# =======================
# FUNGSI UTAMA
# =======================
def monitor_domain():
    days_left = check_ssl(DOMAIN)
    status = check_http(DOMAIN)

    if days_left is not None and days_left < 15:
        logging.warning(f"SSL hampir expired ({days_left} hari). Auto-renew...")
        subprocess.run(["sudo", "certbot", "renew", "--quiet"])
    
    if status != 200:
        logging.warning(f"HTTP Error: {status}. Restart Nginx...")
        subprocess.run(["sudo", "systemctl", "restart", "nginx"])
    
    tampered = scan_integrity()
    if tampered:
        logging.warning("File domain dicurigai diubah. Restore backup...")
        backup_files()
    
    logging.info(f"Monitoring done. SSL days left: {days_left}, HTTP status: {status}")

# =======================
# LOOP UTAMA
# =======================
if __name__ == "__main__":
    backup_files()  # backup awal
    while True:
        monitor_domain()
        time.sleep(CHECK_INTERVAL)
