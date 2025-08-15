import socket
import threading
import datetime
import smtplib
from email.message import EmailMessage
import requests
import time
import re
import base64

# ------------------------ CONFIGURATION ------------------------ #
LOG_FILE = "honeypot_logs.txt"
HOST = "0.0.0.0"
PORT = 2222

FROM_EMAIL = "aalageely@gmail.com"
TO_EMAIL = "danaalageely@gmail.com"
APP_PASSWORD = "mkbc nxsa upag uqzs"

TELEGRAM_TOKEN = "8389627211:AAGq6tuHxuLKX9m4AQR-ljj77z-GjKrpIig"
CHAT_ID = "1919975349"

FIREBASE_URL = "https://honeypot-715b9-default-rtdb.firebaseio.com/honeypot_logs.json"

# ------------------------ ATTACK DETECTION ------------------------ #
def detect_attack(payload):
    if not payload or payload.strip() == "":
        return "Empty Connection"

    payload_lower = payload.lower().strip()
    
    if payload.startswith("SSH-"):
        version = payload.split()[0] if " " in payload else payload.strip()
        return f"SSH Connection - {version}"
    
    nmap_patterns = ["nmap", "masscan", "zmap", "unicornscan"]
    if any(tool in payload_lower for tool in nmap_patterns):
        for tool in nmap_patterns:
            if tool in payload_lower:
                return f"Port Scan - {tool.upper()}"
    
    netcat_patterns = ["ncat", "netcat", "nc ", "nc.exe"]
    if any(tool in payload_lower for tool in netcat_patterns):
        for tool in netcat_patterns:
            if tool in payload_lower:
                return f"Network Tool - {tool.upper()}"
    
    if "curl" in payload_lower:
        curl_flags = {
            "-x": "Proxy Request",
            "--proxy": "Proxy Request", 
            "-h": "Header Manipulation",
            "--header": "Header Manipulation",
            "-d": "POST Data",
            "--data": "POST Data",
            "-u": "Authentication",
            "--user": "Authentication",
            "-k": "SSL Bypass",
            "--insecure": "SSL Bypass"
        }
        for flag, desc in curl_flags.items():
            if flag in payload_lower:
                return f"Curl - {desc}"
        return "Curl Request"
    
    if "wget" in payload_lower:
        wget_flags = {
            "--spider": "Web Crawling",
            "--mirror": "Site Mirroring",
            "-r": "Recursive Download",
            "--no-check-certificate": "SSL Bypass",
            "-O": "File Download"
        }
        for flag, desc in wget_flags.items():
            if flag in payload_lower:
                return f"Wget - {desc}"
        return "Wget Request"
    
    if "sqlmap" in payload_lower:
        return "SQL Injection - SQLMap Tool"
    
    sql_patterns = [
        (r"union\s+select", "UNION SELECT"),
        (r"select.*from", "SELECT Query"),
        (r"drop\s+table", "DROP TABLE"),
        (r"insert\s+into", "INSERT Query"),
        (r"'\s*or\s*'", "OR Injection"),
        (r"'\s*=\s*'", "Equality Bypass"),
        (r"--", "Comment Injection"),
        (r"/\*.*\*/", "Comment Injection"),
        (r"xp_cmdshell", "Command Execution"),
        (r"sp_executesql", "Stored Procedure")
    ]
    for pattern, attack_name in sql_patterns:
        if re.search(pattern, payload_lower):
            return f"SQL Injection - {attack_name}"
    
    xss_patterns = [
        (r"<script[^>]*>", "Script Tag"),
        (r"javascript:", "JavaScript Protocol"),
        (r"onerror\s*=", "Error Handler"),
        (r"onload\s*=", "Load Handler"),
        (r"alert\s*\(", "Alert Function"),
        (r"document\.cookie", "Cookie Theft"),
        (r"eval\s*\(", "Code Evaluation"),
        (r"<iframe", "IFrame Injection")
    ]
    for pattern, attack_name in xss_patterns:
        if re.search(pattern, payload_lower):
            return f"XSS Attack - {attack_name}"
    
    cmd_patterns = [
        (r";\s*whoami", "Identity Discovery"),
        (r";\s*id", "User Info"),
        (r";\s*ls", "Directory Listing"),
        (r";\s*cat", "File Reading"),
        (r";\s*ping", "Network Test"),
        (r"&&\s*whoami", "Command Chaining"),
        (r"\|\s*whoami", "Pipe Command"),
        (r"`whoami`", "Command Substitution"),
        (r"cmd\.exe", "Windows Command"),
        (r"powershell", "PowerShell"),
        (r"/bin/bash", "Bash Shell"),
        (r"/bin/sh", "Shell Access")
    ]
    for pattern, attack_name in cmd_patterns:
        if re.search(pattern, payload_lower):
            return f"Command Injection - {attack_name}"
    
    webshell_patterns = [
        (r"c99\.php", "C99 Shell"),
        (r"r57\.php", "R57 Shell"),
        (r"shell\.php", "Generic Shell"),
        (r"cmd\.php", "Command Shell"),
        (r"eval\s*\(\$_", "PHP Eval"),
        (r"system\s*\(\$_", "System Command"),
        (r"exec\s*\(\$_", "Execute Command")
    ]
    for pattern, attack_name in webshell_patterns:
        if re.search(pattern, payload_lower):
            return f"Web Shell - {attack_name}"
    
    auth_keywords = ["admin", "root", "password", "login", "user", "pass", "administrator"]
    if any(keyword in payload_lower for keyword in auth_keywords):
        if any(protocol in payload_lower for protocol in ["ssh-", "ftp", "telnet"]):
            return "Brute Force - Credential Attack"
        return "Authentication Probe"
    
    traversal_patterns = [
        ("../", "Unix Path Traversal"),
        ("..\\", "Windows Path Traversal"),
        ("%2e%2e", "URL Encoded Traversal"),
        ("....//", "Double Dot Traversal")
    ]
    for pattern, attack_name in traversal_patterns:
        if pattern in payload_lower:
            return f"Directory Traversal - {attack_name}"
    
    inclusion_patterns = [
        ("file://", "Local File Inclusion"),
        ("php://", "PHP Wrapper"),
        ("data://", "Data Wrapper"),
        ("expect://", "Expect Wrapper")
    ]
    for pattern, attack_name in inclusion_patterns:
        if pattern in payload_lower:
            return f"File Inclusion - {attack_name}"
    
    http_methods = ["get ", "post ", "put ", "delete ", "head ", "options ", "patch "]
    for method in http_methods:
        if payload_lower.startswith(method):
            return f"HTTP Request - {method.strip().upper()}"
    
    ftp_commands = {
        "user ": "FTP Login",
        "pass ": "FTP Password",
        "list": "FTP Directory List",
        "retr ": "FTP Download",
        "stor ": "FTP Upload"
    }
    for cmd, desc in ftp_commands.items():
        if cmd in payload_lower:
            return f"FTP Command - {desc}"
    
    if any(char in payload for char in ['\xff', '\xfe', '\xfd']):
        return "Telnet Protocol Negotiation"
    
    try:
        if '%' in payload and len(payload) > 10:
            decoded = requests.utils.unquote(payload)
            if decoded != payload and len(decoded) > 5:
                detected_type = detect_attack(decoded)
                if detected_type != "Unknown":
                    return f"{detected_type} (URL Encoded)"
    except:
        pass
    
    try:
        if len(payload) > 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in payload):
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded and len(decoded) > 5:
                detected_type = detect_attack(decoded)
                if detected_type != "Unknown":
                    return f"{detected_type} (Base64 Encoded)"
    except:
        pass
    
    if len(payload) > 1000:
        if payload.count('A') > 100 or payload.count('\\x') > 50:
            return "Buffer Overflow Attempt"
        return "Large Payload Attack"
    
    non_printable_count = sum(1 for c in payload if ord(c) < 32 or ord(c) > 126)
    if non_printable_count > len(payload) * 0.3:
        return "Binary/Non-Printable Data"
    
    if any(word in payload_lower for word in ["scan", "probe", "test"]):
        return "Network Probe"
    
    if len(payload.strip()) < 5:
        return "Short Probe"
    
    return "Suspicious Activity"

# ------------------------ ALERT FUNCTIONS ------------------------ #
def send_email_alert(ip, port, data, attack_type):
    msg = EmailMessage()
    msg["Subject"] = f"🚨 Honeypot Alert - {attack_type} Detected"
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg.set_content(f"""
🚨 Suspicious activity detected on the honeypot:

📍 IP Address: {ip}
📌 Port: {port}
💥 Attack Type: {attack_type}
🕒 Timestamp: {datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')}
🧾 Payload: {data.strip()}
""")
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(FROM_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"[\u2714] Email alert sent to {TO_EMAIL}")
    except Exception as e:
        print(f"[\u2716] Failed to send email: {e}")

def send_telegram_alert(ip, port, data, attack_type):
    message = f"""🚨 *Honeypot Alert Detected*

🔍 *IP:* `{ip}`
🔌 *Port:* `{port}`
💥 *Attack Type:* `{attack_type}`
🕒 *Time:* `{datetime.datetime.now().strftime('%m/%d/%Y %I:%M:%S %p')}`
🧾 *Payload:* `{data.strip()}`"""

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("[\u2714] Telegram alert sent.")
        else:
            print(f"[\u2716] Telegram failed: {response.text}")
    except Exception as e:
        print(f"[\u2716] Telegram error: {e}")

def send_to_firebase(ip, port, data, attack_type):
    payload = {
        "ip": ip,
        "port": port,
        "time": int(time.time() * 1000),
        "data": data.strip(),
        "attack_type": attack_type
    }
    try:
        r = requests.post(FIREBASE_URL, json=payload)
        if r.status_code == 200:
            print("[\u2714] Sent to Firebase")
        else:
            print(f"[\u2716] Firebase failed: {r.text}")
    except Exception as e:
        print(f"[\u2716] Firebase error: {e}")

# ------------------------ LOGGING FUNCTION ------------------------ #
def log_attempt(addr, data, attack_type):
    timestamp = datetime.datetime.now()
    log = f"[{timestamp}] Connection from {addr[0]}:{addr[1]} - Data: {data.strip()} - Attack Type: {attack_type}"
    print(log)

    with open(LOG_FILE, "a") as f:
        f.write(log + "\n")

    send_email_alert(addr[0], addr[1], data, attack_type)
    send_telegram_alert(addr[0], addr[1], data, attack_type)
    send_to_firebase(addr[0], addr[1], data, attack_type)

# ------------------------ CLIENT HANDLER ------------------------ #
def handle_client(client_socket, addr):
    client_socket.sendall(b"SSH-2.0-OpenSSH_7.9p1 Debian\n")
    try:
        data = client_socket.recv(1024)
        decoded_data = data.decode("utf-8", errors="ignore").strip()

        if not decoded_data:
            decoded_data = "<NO PAYLOAD>"

        attack_type = detect_attack(decoded_data)
        log_attempt(addr, decoded_data, attack_type)

    except Exception as e:
        print(f"[!] Error reading data: {e}")
        log_attempt(addr, "ERROR READING DATA", "Unknown")

    client_socket.close()

# ------------------------ MAIN HONEYPOT ------------------------ #
def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[+] SSH Honeypot running on port {PORT}...")

    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

if __name__ == "__main__":
    start_honeypot()
