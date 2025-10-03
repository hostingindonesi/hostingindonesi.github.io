#!/usr/bin/env python3
"""
domain_audit.py
Simple domain security auditor for HTTPS + headers + subdomain checks.

Usage:
    python domain_audit.py --domain rupiahid-dompet.my.id --json-out report.json
"""

import argparse
import json
import socket
import ssl
import sys
import datetime
import traceback
from urllib.parse import urljoin

try:
    import requests
except Exception:
    print("Missing dependency 'requests'. Install: pip install requests")
    sys.exit(1)

try:
    import dns.resolver
    DNSPYTHON_AVAILABLE = True
except Exception:
    DNSPYTHON_AVAILABLE = False

# ---------- Configuration ----------
COMMON_SUBDOMAINS = [
    "www", "api", "app", "mail", "m", "admin", "secure", "portal", "blog",
    "dev", "staging", "oauth", "cdn", "ftp", "imap", "smtp", "test"
]
REQUEST_TIMEOUT = 8  # seconds
# -----------------------------------

def fetch_headers(domain):
    results = {}
    http = f"http://{domain}"
    https = f"https://{domain}"

    try:
        r = requests.get(http, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        results['http_status'] = r.status_code
        results['http_final_url'] = r.url
        results['http_headers'] = dict(r.headers)
    except Exception as e:
        results['http_error'] = str(e)

    try:
        r2 = requests.get(https, timeout=REQUEST_TIMEOUT, allow_redirects=True, verify=True)
        results['https_status'] = r2.status_code
        results['https_final_url'] = r2.url
        results['https_headers'] = dict(r2.headers)
    except requests.exceptions.SSLError as e:
        results['https_error'] = "SSL_ERROR: " + str(e)
    except Exception as e:
        results['https_error'] = str(e)

    return results

def analyze_security_headers(headers):
    h = {k.lower(): v for k, v in (headers or {}).items()}
    report = {}
    report['hsts'] = h.get('strict-transport-security')
    report['csp'] = h.get('content-security-policy')
    report['x_frame_options'] = h.get('x-frame-options')
    report['x_content_type_options'] = h.get('x-content-type-options')
    report['referrer_policy'] = h.get('referrer-policy')
    report['permissions_policy'] = h.get('permissions-policy') or h.get('x-permissions-policy')
    report['has_hsts'] = bool(report['hsts'])
    report['has_csp'] = bool(report['csp'])
    report['has_secure_headers_minimum'] = all([
        report['has_hsts'],
        report['x_content_type_options'] is not None,
        report['x_frame_options'] is not None
    ])
    return report

def get_cert_via_ssl(domain, port=443, timeout=8):
    info = {}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info['tls_negotiated_version'] = ssock.version()
                info['cert'] = cert
                not_after = cert.get('notAfter')
                if not_after:
                    dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    info['cert_not_after'] = dt.isoformat()
                    info['cert_days_left'] = (dt - datetime.datetime.utcnow()).days
    except Exception as e:
        info['error'] = str(e)
    return info

def test_tls_versions(domain, port=443, timeout=6):
    versions = {}
    candidates = [
        ("TLSv1.3", getattr(ssl, "TLSVersion", None) and (ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)),
        ("TLSv1.2", getattr(ssl, "TLSVersion", None) and (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)),
        ("TLSv1.1", getattr(ssl, "TLSVersion", None) and (ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1)),
        ("TLSv1",   getattr(ssl, "TLSVersion", None) and (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1)),
    ]
    for name, bounds in candidates:
        if not bounds:
            versions[name] = "unavailable_in_runtime"
            continue
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            context.minimum_version, context.maximum_version = bounds
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    versions[name] = True
        except ssl.SSLError:
            versions[name] = False
        except Exception as e:
            versions[name] = f"error: {e}"
    return versions

def check_subdomains(domain, list_subs=None, timeout=3):
    list_subs = list_subs or COMMON_SUBDOMAINS
    results = {}
    for sub in list_subs:
        fqdn = f"{sub}.{domain}"
        try:
            if DNSPYTHON_AVAILABLE:
                answers = dns.resolver.resolve(fqdn, 'A', lifetime=timeout)
                ips = [r.to_text() for r in answers]
            else:
                ips = [socket.gethostbyname(fqdn)]
            results[fqdn] = {"resolved": True, "ips": ips}
        except Exception:
            results[fqdn] = {"resolved": False}
    return results

def run_audit(domain, subdomains=None):
    out = {"domain": domain, "timestamp_utc": datetime.datetime.utcnow().isoformat()}
    try:
        headers_info = fetch_headers(domain)
        out['headers_check'] = headers_info

        https_headers = headers_info.get('https_headers') or {}
        out['security_headers_analysis'] = analyze_security_headers(https_headers)

        cert_info = get_cert_via_ssl(domain)
        out['cert'] = cert_info

        out['tls_versions'] = test_tls_versions(domain)

        out['subdomains'] = check_subdomains(domain, list_subs=subdomains)

        notes = []
        if 'https_error' in headers_info:
            notes.append("HTTPS fetch error: " + str(headers_info['https_error']))
        if out['cert'].get('cert_days_left') is not None and out['cert']['cert_days_left'] < 14:
            notes.append(f"Certificate expires in {out['cert']['cert_days_left']} days — renew soon.")
        if not out['security_headers_analysis']['has_hsts']:
            notes.append("HSTS not present — consider enabling Strict-Transport-Security header.")
        out['notes'] = notes

    except Exception as e:
        out['error'] = str(e)
        out['traceback'] = traceback.format_exc()
    return out

def main():
    p = argparse.ArgumentParser(description="Domain security auditor (SSL, headers, subdomains).")
    p.add_argument("--domain", required=True, help="Domain to audit, e.g. rupiahid-dompet.my.id")
    p.add_argument("--json-out", help="Write JSON report to file")
    p.add_argument("--subdomains-file", help="Optional newline-separated file with subdomains to test")
    args = p.parse_args()

    subdomains = None
    if args.subdomains_file:
        with open(args.subdomains_file, "r") as f:
            subdomains = [ln.strip() for ln in f if ln.strip()]

    report = run_audit(args.domain, subdomains=subdomains)

    print("==== Domain Audit Summary ====")
    print(f"Domain: {report.get('domain')}")
    cert = report.get('cert', {})
    if cert.get('cert_not_after'):
        print(f"Cert expires: {cert['cert_not_after']} UTC ({cert.get('cert_days_left')} days left)")
    else:
        print("Cert: unavailable / error:", cert.get('error'))
    headers_summary = report.get('security_headers_analysis', {})
    print("HSTS:", headers_summary.get('hsts') is not None)
    print("CSP:", headers_summary.get('csp') is not None)
    print("Basic secure headers present:", headers_summary.get('has_secure_headers_minimum'))
    print("TLS version support test:", report.get('tls_versions'))
    print("Notes:", report.get('notes'))

    if args.json_out:
        with open(args.json_out, "w") as f:
            json.dump(report, f, indent=2, sort_keys=True, default=str)
        print("JSON report written to", args.json_out)

if __name__ == "__main__":
    main()
