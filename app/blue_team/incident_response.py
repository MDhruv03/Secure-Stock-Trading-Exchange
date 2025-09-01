
import re
import os

def parse_and_block_ips(log_file, blocklist_file):
    """Parses a log file for IDS alerts and blocks the attacker's IP."""
    with open(log_file, 'r') as f:
        alerts = f.readlines()

    blocked_ips = set()
    if os.path.exists(blocklist_file):
        with open(blocklist_file, 'r') as f:
            for ip in f.readlines():
                blocked_ips.add(ip.strip())

    ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    for alert in alerts:
        match = ip_pattern.search(alert)
        if match:
            ip = match.group(1)
            if ip not in blocked_ips:
                print(f"Blocking IP: {ip}")
                with open(blocklist_file, 'a') as f:
                    f.write(f"{ip}\n")
                blocked_ips.add(ip)
            else:
                print(f"IP already blocked: {ip}")

if __name__ == '__main__':
    script_dir = os.path.dirname(__file__)
    log_file = os.path.abspath(os.path.join(script_dir, '..', '..', 'data', 'ids_alerts.log'))
    blocklist_file = os.path.abspath(os.path.join(script_dir, '..', '..', 'data', 'blocked_ips.txt'))
    parse_and_block_ips(log_file, blocklist_file)
