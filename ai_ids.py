from scapy.all import sniff
import pickle
import numpy as np
import requests
import os

# =========================
# TELEGRAM CONFIG
# =========================
BOT_TOKEN = "8629967549:AAGq_5Xu_p9RskUtro-OnQL8fRKTAUJio"
CHAT_ID = "8592091427"

def send_alert(message):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    data = {"chat_id": CHAT_ID, "text": message}
    try:
        requests.post(url, data=data)
    except:
        pass

# =========================
# LOAD ML MODEL
# =========================
model = pickle.load(open("rf_model.pkl", "rb"))

# =========================
# ALLOWED WEBSITES
# =========================
ALLOWED_SITES = [
    "youtube.com",
    "chatgpt.com",
    "gmail.com",
    "google.com"
]

# =========================
# FEATURE EXTRACTION
# =========================
def extract_features(packet):
    try:
        length = len(packet)

        proto = 0
        if packet.haslayer("TCP"):
            proto = 1
        elif packet.haslayer("UDP"):
            proto = 2

        features = [length, proto, 1, 1, length]

        return np.array(features).reshape(1, -1)
    except:
        return None

# =========================
# PHISHING DETECTION
# =========================
def detect_phishing(packet):
    if packet.haslayer("DNS"):
        try:
            query = packet["DNS"].qd.qname.decode(errors="ignore").lower()

            keywords = ["login", "verify", "bank", "secure", "update", "account"]

            for word in keywords:
                if word in query:
                    return True, query
        except:
            pass

    return False, None

# =========================
# WEBSITE ACCESS CONTROL
# =========================
def check_allowed_website(packet):
    if packet.haslayer("DNS"):
        try:
            query = packet["DNS"].qd.qname.decode(errors="ignore").lower()

            if not any(site in query for site in ALLOWED_SITES):
                return False, query
            else:
                return True, query
        except:
            pass

    return True, None

# =========================
# BLOCK IP USING IPTABLES
# =========================
def block_ip(ip):
    try:
        os.system(f"sudo iptables -A OUTPUT -d {ip} -j DROP")
    except:
        pass

# =========================
# MAIN PACKET PROCESSOR
# =========================
def process_packet(packet):

    if packet.haslayer("IP"):

        src = packet["IP"].src

        # 🔐 WEBSITE CONTROL
        allowed, domain = check_allowed_website(packet)

        if domain is not None and not allowed:
            msg = f"🚫 Blocked Website Access: {domain}"
            print(msg)
            send_alert(msg)

            block_ip(src)
            return

        # 🎣 PHISHING DETECTION
        is_phishing, domain = detect_phishing(packet)

        if is_phishing:
            msg = f"🎣 Phishing Detected!\nDomain: {domain}"
            print(msg)
            send_alert(msg)
            block_ip(src)
            return

        # 🤖 ML DOS DETECTION
        features = extract_features(packet)

        if features is not None:
            prediction = model.predict(features)[0]

            if prediction == 1:
                msg = f"🚨 DoS Attack Detected → {packet.summary()}"
                print(msg)
                send_alert(msg)
                block_ip(src)
            else:
                print(f"Normal → {packet.summary()}")

# =========================
# START IDS
# =========================
print("🚀 AI IDS + Access Control Running...")

sniff(prn=process_packet)
