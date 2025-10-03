import requests, ssl, socket, datetime, subprocess

DOMAIN = "rupiahid-dompet.my.id"

def check_ssl(domain):
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
        s.connect((domain, 443))
        cert = s.getpeercert()
        expire = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        days_left = (expire - datetime.datetime.utcnow()).days
        return days_left

def check_http(domain):
    try:
        r = requests.get("https://" + domain, timeout=10)
        return r.status_code
    except Exception as e:
        return str(e)

days_left = check_ssl(DOMAIN)
status = check_http(DOMAIN)

if days_left < 15:
    print(f"⚠️ SSL hampir expired ({days_left} hari). Auto-renew...")
    subprocess.run(["sudo", "certbot", "renew", "--quiet"])

if status != 200:
    print(f"⚠️ HTTP Error: {status}. Restart Nginx...")
    subprocess.run(["sudo", "systemctl", "restart", "nginx"])

print("✅ Monitoring done.")
