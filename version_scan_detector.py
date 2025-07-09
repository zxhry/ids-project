from scapy.all import *
from collections import defaultdict
import time
import requests

# === Telegram Bot Config ===
TELEGRAM_BOT_TOKEN = 'your_telegram_bot_token'
TELEGRAM_CHAT_ID = 'your_chat_id'
TELEGRAM_API_URL = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

# === Detection Thresholds ===
SCAN_WINDOW = 10  # seconds
PORT_THRESHOLD = 10  # unique ports probed before alert

# === Store scan attempts ===
scan_activity = defaultdict(lambda: {'timestamps': [], 'ports': set()})

def send_telegram_alert(ip, ports):
    message = (
        f"🚨 *Possible Nmap Version Scan Detected!*\n\n"
        f"🔍 Source IP: `{ip}`\n"
        f"📍 Ports Probed: `{sorted(ports)}`\n"
        f"🕒 Time: {time.strftime('%Y-%m-%d %H:%M:%S')}"
    )
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        requests.post(TELEGRAM_API_URL, data=payload)
    except Exception as e:
        print(f"[!] Failed to send Telegram alert: {e}")

def detect_nmap_scan(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        now = time.time()

        scan_activity[src_ip]['timestamps'].append(now)
        scan_activity[src_ip]['ports'].add(dst_port)

        # Clean old entries
        scan_activity[src_ip]['timestamps'] = [
            t for t in scan_activity[src_ip]['timestamps'] if now - t <= SCAN_WINDOW
        ]

        # Trigger alert
        if len(scan_activity[src_ip]['ports']) >= PORT_THRESHOLD:
            print(f"[!] Nmap version scan detected from {src_ip}")
            send_telegram_alert(src_ip, scan_activity[src_ip]['ports'])
            scan_activity[src_ip]['ports'].clear()  # Reset after alert

print("[*] Sniffing for Nmap version scan attempts (Ctrl+C to stop)...")
sniff(filter="tcp", prn=detect_nmap_scan, store=0)