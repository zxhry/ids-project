from scapy.all import sniff, TCP, IP
import requests 

# Telegram config
TELEGRAM_BOT_TOKEN = 'your_telegram_bot_token'
TELEGRAM_CHAT_ID = 'your_chat_id'

# List of known suspicious window sizes commonly used by Nmap
SUSPICIOUS_WINDOW_SIZES = [0, 1024, 2048, 4096]

def send_telegram_alert(message):
    url = f'https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage'
    payload = {
        'chat_id': TELEGRAM_CHAT_ID,
        'text': message,
        'parse_mode': 'Markdown'
    }
    try:
        requests.post(url, data=payload)
    except Exception as e:
        print(f"[!] Failed to send Telegram alert: {e}")

def detect_nmap_window_scan(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        tcp = packet[TCP]
        ip = packet[IP]
        
        # Check for ACK-only packets (possible Window scan)
        if tcp.flags == 'A':
            window_size = tcp.window
            src_ip = ip.src
            dst_ip = ip.dst
            dst_port = tcp.dport

            if window_size in SUSPICIOUS_WINDOW_SIZES:
                alert = (
                    f"🚨 *Nmap Window Scan Detected!*\n"
                    f"• Source IP: `{src_ip}`\n"
                    f"• Destination: `{dst_ip}:{dst_port}`\n"
                    f"• TCP Window Size: `{window_size}`"
                )
                print(alert)
                send_telegram_alert(alert)

print("[*] Nmap Window Scan Detector with Telegram Alerts Started...")
sniff(filter="tcp", prn=detect_nmap_window_scan, store=0)