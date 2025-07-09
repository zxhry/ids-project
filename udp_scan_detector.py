from scapy.all import sniff, IP, UDP
import requests
from collections import defaultdict
import time

# === Telegram Bot Config ===
bot_token = 'your_telegram_bot_token'
chat_id = 'your_chat_id'

# === Attacker IP to Track ===
ATTACKER_IP = 'your_attacker_ip'

# === Alert via Telegram ===
def send_alert(message):
    url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
    payload = {'chat_id': chat_id, 'text': message}
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        print("✅ Telegram alert sent!")
    else:
        print(f"❌ Failed to send alert: {response.text}")

# === UDP Scan Detection ===
udp_count = defaultdict(int)
udp_time = defaultdict(float)

def detect_udp_scan(pkt):
    current_time = time.time()

    if IP in pkt and UDP in pkt:
        ip_src = pkt[IP].src

        # Only track attacker
        if ip_src != ATTACKER_IP:
            return

        key = ip_src + "_udp"
        udp_count[key] += 1
        udp_time.setdefault(key, current_time)

        dport = pkt[UDP].dport
        print(f"[DEBUG] UDP packet from {ip_src} to port {dport}")

        # Alert if more than 20 UDP packets sent in under 10 seconds
        if udp_count[key] > 20 and current_time - udp_time[key] < 10:
            send_alert(f"⚠ UDP Port Scan Detected from {ip_src}")
            udp_count[key] = 0  # reset
            udp_time[key] = current_time
        else:
            udp_time[key] = current_time

# === Start Sniffing ===
print("📡 IDS running — monitoring UDP scans from attacker IP your_attacker_ip")
sniff(filter="udp", prn=detect_udp_scan, store=0)