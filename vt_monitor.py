#!/usr/bin/env python3
import argparse
import configparser
import psycopg2
import requests
import schedule
import time
import re
import sys
from datetime import datetime
from typing import List

# ----------------------------------------------------------
# 1. Read config.ini
# ----------------------------------------------------------
config = configparser.ConfigParser()
config.read('config.ini')

DB_HOST = config.get('DATABASE', 'host', fallback='localhost')
DB_PORT = config.get('DATABASE', 'port', fallback='5432')
DB_NAME = config.get('DATABASE', 'database', fallback='vt_monitor')
DB_USER = config.get('DATABASE', 'user', fallback='vt_user')
DB_PASSWORD = config.get('DATABASE', 'password', fallback='vt_password')

API_KEYS = config.get('API', 'vt_keys', fallback='').split(',')
API_KEYS = [key.strip() for key in API_KEYS if key.strip()]

DISCORD_WEBHOOK = config.get('DISCORD', 'discord_webhook', fallback=None)

# Delay in seconds between consecutive API calls
SCAN_DELAY = float(config.get('SETTINGS', 'scan_delay', fallback=15))

# Monitoring interval in minutes (default = 4 days = 5760 minutes)
MONITOR_INTERVAL = int(config.get('SETTINGS', 'monitor_interval', fallback=5760))

# ----------------------------------------------------------
# 2. Juicy Patterns
# ----------------------------------------------------------
JUICY_FILE_EXTENSIONS = [
    '.zip', '.7z', '.exe', '.tar', '.gz', '.dll', '.iso',
    '.pem', '.env', '.bak', '.backup'
]
SENSITIVE_KEYWORDS = [
    'token=', 'apikey=', '/resetpassword/', 'registration',
    '==', '.com:', '@', 'code=', '.aspx', '.ashx', '.php',
    '.jsp', '.cgi', '.xml', '.txt', '.xhtml',
    'secret=', 'password=', 'pwd=', 'PRIVATE_KEY', 'RSA PRIVATE KEY'
]

CREDENTIALS_REGEX = re.compile(r'(https?:\/\/[^\s\/]+\/:[^:\s]+:[^:\s]+)', re.IGNORECASE)

# ----------------------------------------------------------
# 3. Database Helper Functions
# ----------------------------------------------------------
def get_db_connection():
    """
    Create and return a new database connection (psycopg2).
    """
    conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )
    return conn

def add_domain_to_monitor(domain: str):
    """
    Insert a domain into 'monitored_domains' if it doesn't already exist.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO monitored_domains (domain)
                VALUES (%s)
                ON CONFLICT (domain) DO NOTHING
            """, (domain,))
        conn.commit()
        print(f"[INFO] Added domain '{domain}' for monitoring.")
    except Exception as e:
        print(f"[ERROR] Cannot add domain '{domain}': {e}")
    finally:
        if conn:
            conn.close()

def remove_domain_from_monitor(domain: str):
    """
    Remove a domain from 'monitored_domains'.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                DELETE FROM monitored_domains
                WHERE domain = %s
            """, (domain,))
        conn.commit()
        print(f"[INFO] Removed domain '{domain}' from monitoring.")
    except Exception as e:
        print(f"[ERROR] Cannot remove domain '{domain}': {e}")
    finally:
        if conn:
            conn.close()

def get_monitored_domains() -> List[str]:
    """
    Retrieve the list of domains currently in 'monitored_domains'.
    """
    domains = []
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("SELECT domain FROM monitored_domains ORDER BY domain ASC")
            rows = cur.fetchall()
            domains = [row[0] for row in rows]
    except Exception as e:
        print(f"[ERROR] Cannot fetch monitored domains: {e}")
    finally:
        if conn:
            conn.close()
    return domains

def update_last_scan(domain: str):
    """
    Update the last_scan timestamp for a given domain after scanning.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE monitored_domains
                SET last_scan = %s
                WHERE domain = %s
            """, (datetime.utcnow(), domain))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Cannot update last_scan for domain '{domain}': {e}")
    finally:
        if conn:
            conn.close()

def save_findings_to_db(domain: str, findings: List[str]):
    """
    Save the discovered findings into 'scan_findings', ignoring duplicates.
    """
    if not findings:
        return

    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            for finding in findings:
                cur.execute("""
                    INSERT INTO scan_findings (domain, finding)
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING
                """, (domain, finding))
        conn.commit()
    except Exception as e:
        print(f"[ERROR] Cannot save findings for domain '{domain}': {e}")
    finally:
        if conn:
            conn.close()

def get_findings_for_domain(domain: str) -> List[str]:
    """
    Return all findings from 'scan_findings' for a specific domain,
    ordered by found_at (descending).
    """
    conn = None
    findings = []
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT finding, found_at FROM scan_findings
                WHERE domain = %s
                ORDER BY found_at DESC
            """, (domain,))
            rows = cur.fetchall()
            for row in rows:
                finding_text, found_at = row
                # We'll handle final formatting in the printing logic.
                # Just store the data here.
                findings.append((finding_text, found_at))
    except Exception as e:
        print(f"[ERROR] Cannot fetch findings for domain '{domain}': {e}")
    finally:
        if conn:
            conn.close()
    return findings

# ----------------------------------------------------------
# 4. Scanning & Parsing
# ----------------------------------------------------------
def search_juicy_data_in_string(text: str) -> List[str]:
    """
    Searches for any of the specified patterns in the given text.
    Returns a list of matched patterns or references.
    """
    results = []

    # 1. Check for file extensions
    for ext in JUICY_FILE_EXTENSIONS:
        if ext.lower() in text.lower():
            results.append(f"Found file extension '{ext}' in: {text}")

    # 2. Check for sensitive keywords
    for keyword in SENSITIVE_KEYWORDS:
        if keyword.lower() in text.lower():
            results.append(f"Found keyword '{keyword}' in: {text}")

    # 3. Check for credential patterns
    creds_match = CREDENTIALS_REGEX.findall(text)
    if creds_match:
        for match in creds_match:
            results.append(f"Potential leaked credential pattern in: {match}")

    return results

def parse_vt_response(domain: str, json_data: dict) -> List[str]:
    """
    Parse VirusTotal JSON data for the domain.
    Extract URLs or filenames to search for 'juicy' info.
    Returns a list of all findings for this domain.
    """
    all_findings = []

    keys_of_interest = [
        'undetected_urls', 'detected_urls',
        'subdomains',
        'detected_referrer_samples', 'undetected_referrer_samples'
    ]

    for key in keys_of_interest:
        if key in json_data:
            data_block = json_data[key]

            # 'undetected_urls' or 'detected_urls' are often lists of [url, timestamp]
            if key in ['undetected_urls', 'detected_urls']:
                for item in data_block:
                    if isinstance(item, list) and len(item) > 0:
                        url = str(item[0])
                        findings = search_juicy_data_in_string(url)
                        all_findings.extend(findings)

            # 'subdomains' is typically a list of subdomain strings
            elif key == 'subdomains':
                for subdomain in data_block:
                    findings = search_juicy_data_in_string(subdomain)
                    all_findings.extend(findings)

            # 'detected_referrer_samples' / 'undetected_referrer_samples'
            else:
                for sample in data_block:
                    if isinstance(sample, dict) and 'filename' in sample:
                        filename = sample['filename']
                        findings = search_juicy_data_in_string(filename)
                        all_findings.extend(findings)

    return all_findings

def scan_domain(domain: str, api_key: str) -> List[str]:
    """
    Scans a single domain using the VirusTotal API and returns any discovered sensitive data.
    """
    url = "https://www.virustotal.com/vtapi/v2/domain/report"
    params = {
        'apikey': api_key,
        'domain': domain
    }
    try:
        response = requests.get(url, params=params, timeout=30)
        if response.status_code == 200:
            data = response.json()
            return parse_vt_response(domain, data)
        else:
            print(f"[ERROR] Domain: {domain}, HTTP Status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Request failed for {domain}: {e}")
    return []

# ----------------------------------------------------------
# 5. Discord Notification (with chunking to avoid 2000 limit)
# ----------------------------------------------------------
def send_discord_notification(content: str):
    """
    Send a message to Discord via the webhook if it's configured.
    """
    if not DISCORD_WEBHOOK:
        print("[WARN] Discord webhook not configured.")
        return

    # Basic HTTP post with JSON
    payload = {
        "content": content
    }
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload)
        if r.status_code not in [200, 204]:
            print(f"[ERROR] Discord message status: {r.status_code}, Text: {r.text}")
    except Exception as e:
        print(f"[ERROR] Exception while sending Discord message: {e}")

def send_discord_in_chunks(message: str, max_len: int = 2000):
    """
    Discord's 'content' field must be <= 2000 chars.
    We'll split our message into multiple chunks if needed.
    """
    lines = message.split("\n")
    chunk = ""
    for line in lines:
        # If adding this line exceeds the limit, send the current chunk first.
        if len(chunk) + len(line) + 1 > max_len:
            send_discord_notification(chunk)
            chunk = ""
        # Add a newline if 'chunk' isn't empty
        if chunk:
            chunk += "\n" + line
        else:
            chunk = line

    # Send the remaining chunk
    if chunk:
        send_discord_notification(chunk)

# ----------------------------------------------------------
# 6. Round-Robin API Key Handling
# ----------------------------------------------------------
api_key_index = 0
def get_next_apikey() -> str:
    global api_key_index
    if not API_KEYS:
        print("[ERROR] No API keys found in config.ini.")
        sys.exit(1)

    key = API_KEYS[api_key_index]
    api_key_index = (api_key_index + 1) % len(API_KEYS)
    return key

# ----------------------------------------------------------
# 7. Single-Scan Mode
# ----------------------------------------------------------
def single_scan(domains: List[str]):
    """
    Perform a one-time scan of the provided domains (one-shot).
    """
    for domain in domains:
        api_key = get_next_apikey()
        findings = scan_domain(domain, api_key)
        if findings:
            print(f"\n[+] Juicy Findings for domain: {domain}")
            # Print each finding, separated by lines
            for finding in findings:
                print(f"    {finding}")
                print("="*100)
        else:
            print(f"\n[-] No juicy data found for domain: {domain}")

        time.sleep(SCAN_DELAY)

# ----------------------------------------------------------
# 8. Monitoring (Scheduled) Mode
# ----------------------------------------------------------
def monitor_scan():
    """
    Periodically scans all domains in the 'monitored_domains' table.
    Any new findings are saved to DB and posted to Discord in chunks.
    """
    domains = get_monitored_domains()
    if not domains:
        print("[INFO] No domains to monitor.")
        return

    for domain in domains:
        # For each domain, show a line with domain + timestamp
        print(f"[INFO] Scanning domain: {domain} at {datetime.utcnow()}")
        api_key = get_next_apikey()
        findings = scan_domain(domain, api_key)

        # Save to DB (only new findings) + update last scan
        if findings:
            save_findings_to_db(domain, findings)

            # Build a Discord message for this domain
            # We'll do a short header + the findings
            lines = [f"**Monitoring Report for** `{domain}`:\n"]
            for f in findings:
                lines.append(f"- {f}")
            final_message = "\n".join(lines)

            # Send in chunks to Discord if too large
            send_discord_in_chunks(final_message)

        update_last_scan(domain)
        time.sleep(SCAN_DELAY)

def start_monitoring():
    """
    Start the monitoring loop using the 'schedule' library.
    The interval is defined by MONITOR_INTERVAL (in minutes).
    """
    schedule.every(MONITOR_INTERVAL).minutes.do(monitor_scan)
    print(f"[INFO] Monitoring started. Interval = {MONITOR_INTERVAL} minutes "
          f"({MONITOR_INTERVAL / (60*24):.2f} days).")
    while True:
        schedule.run_pending()
        time.sleep(1)

# ----------------------------------------------------------
# 9. Helper to Read Domains from File
# ----------------------------------------------------------
def read_domains_from_file(path: str) -> List[str]:
    """
    Returns a list of domains from a text file, one per line.
    """
    domain_list = []
    try:
        with open(path, 'r') as f:
            for line in f:
                d = line.strip()
                if d:
                    domain_list.append(d)
    except Exception as e:
        print(f"[ERROR] Cannot read file '{path}': {e}")
    return domain_list

# ----------------------------------------------------------
# 10. Main CLI Logic (Argparse)
# ----------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="VirusTotal Domain Scanner & Monitoring Tool")
    subparsers = parser.add_subparsers(dest='command')

    # ------------------------------------------------------
    # 10a. Add Domain(s) to Monitoring
    # ------------------------------------------------------
    parser_add = subparsers.add_parser('add', help="Add domain(s) to the monitoring list")
    parser_add.add_argument('-d', '--domain', help="Single domain to add")
    parser_add.add_argument('-f', '--file', help="File containing domains to add")

    # ------------------------------------------------------
    # 10b. Single-scan Mode
    # ------------------------------------------------------
    parser_scan = subparsers.add_parser('scan', help="Perform a one-time scan of provided domains")
    parser_scan.add_argument('-d', '--domain', help="Single domain to scan")
    parser_scan.add_argument('-f', '--file', help="File containing domains to scan")

    # ------------------------------------------------------
    # 10c. Monitoring Command
    # ------------------------------------------------------
    parser_monitor = subparsers.add_parser('monitor', help="Run the monitoring scheduler")

    # ------------------------------------------------------
    # 10d. List Monitored Domains
    # ------------------------------------------------------
    parser_list = subparsers.add_parser('list', help="List all monitored domains")

    # ------------------------------------------------------
    # 10e. Remove Domain(s)
    # ------------------------------------------------------
    parser_remove = subparsers.add_parser('remove', help="Remove domain(s) from monitoring list")
    parser_remove.add_argument('-d', '--domain', help="Single domain to remove")
    parser_remove.add_argument('-f', '--file', help="File containing domains to remove")

    # ------------------------------------------------------
    # 10f. View Scan Findings for Domain(s)
    # ------------------------------------------------------
    parser_records = subparsers.add_parser('records', help="View scan records for domain(s)")
    parser_records.add_argument('-d', '--domain', help="Single domain to view records")
    parser_records.add_argument('-f', '--file', help="File with list of domains to view records")

    # ------------------------------------------------------
    # Parse Args and Dispatch
    # ------------------------------------------------------
    args = parser.parse_args()

    if args.command == 'add':
        # Add domain(s) to the DB for monitoring
        domains_to_add = []
        if args.domain:
            domains_to_add.append(args.domain)
        if args.file:
            domains_to_add.extend(read_domains_from_file(args.file))

        if not domains_to_add:
            print("[ERROR] Provide either --domain or --file with valid entries.")
            sys.exit(1)

        for d in domains_to_add:
            add_domain_to_monitor(d)

    elif args.command == 'scan':
        # Single-scan mode
        domains_to_scan = []
        if args.domain:
            domains_to_scan.append(args.domain)
        if args.file:
            domains_to_scan.extend(read_domains_from_file(args.file))

        if not domains_to_scan:
            print("[ERROR] Provide either --domain or --file with valid entries for scanning.")
            sys.exit(1)

        single_scan(domains_to_scan)

    elif args.command == 'monitor':
        # Start the monitoring schedule
        start_monitoring()

    elif args.command == 'list':
        # List all monitored domains
        monitored = get_monitored_domains()
        if monitored:
            print("[INFO] Monitored Domains:")
            for m in monitored:
                print(f" - {m}")
        else:
            print("[INFO] No domains are currently being monitored.")

    elif args.command == 'remove':
        # Remove domain(s) from monitoring list
        domains_to_remove = []
        if args.domain:
            domains_to_remove.append(args.domain)
        if args.file:
            domains_to_remove.extend(read_domains_from_file(args.file))

        if not domains_to_remove:
            print("[ERROR] Provide either --domain or --file with valid entries to remove.")
            sys.exit(1)

        for d in domains_to_remove:
            remove_domain_from_monitor(d)

    elif args.command == 'records':
        # View scan findings for one or more domains
        target_domains = []
        if args.domain:
            target_domains.append(args.domain)
        if args.file:
            target_domains.extend(read_domains_from_file(args.file))

        if not target_domains:
            print("[ERROR] Provide either --domain or --file with valid entries to view records.")
            sys.exit(1)

        for d in target_domains:
            domain_findings = get_findings_for_domain(d)
            if domain_findings:
                print(f"\n[Records for domain: {d}]")
                for (finding_text, found_at) in domain_findings:
                    print(f"{finding_text}")
                    print("="*100)
            else:
                print(f"\n[No findings recorded for domain: {d}]")

    else:
        parser.print_help()

if __name__ == '__main__':
    main()
