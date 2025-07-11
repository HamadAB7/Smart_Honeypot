from dnslib import DNSRecord, QTYPE, RR, A, AAAA, CNAME, MX, TXT
from socketserver import UDPServer, BaseRequestHandler
import logging
from logging.handlers import RotatingFileHandler
from collections import defaultdict
import time
import socket 

# === Logging Setup ===
logger = logging.getLogger("DNSHoneypot")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("log_files/dns_honeypot.log", maxBytes=500000, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# === Custom Responses ===
custom_responses = {
    "login.example.com.": A("10.0.0.10"),
    "admin.corp.net.": A("10.0.0.11"),
    "internal.db.com.": A("10.0.0.12")
}

# === Sensitivity & Alert Parameters ===
sensitive_keywords = ["admin", "internal", "corp", "db", "secret", "vpn", "mail"]
rare_query_types = ["TXT", "AXFR", "CNAME", "MX", "AAAA"]

# Track how many times an IP queries the server
query_counter = defaultdict(int)
query_threshold = 5  # Max allowed queries before alerting

class DNSHandler(BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client_ip = self.client_address[0]
        query_counter[client_ip] += 1

        try:
            request = DNSRecord.parse(data)
        except Exception as e:
            logger.warning(f"Failed to parse DNS request from {client_ip}: {e}")
            return

        query_name = str(request.q.qname)
        query_type = QTYPE[request.q.qtype]

        logger.info(f"IP: {client_ip}, Query: {query_name}, Type: {query_type}")
        print(f"[INFO] Query from {client_ip}: {query_name} ({query_type})")

        # === Alert on Sensitive Domain Keywords ===
        if any(keyword in query_name.lower() for keyword in sensitive_keywords):
            alert = f"[ALERT] 🚨 Sensitive domain queried: {query_name} from IP: {client_ip}"
            print(alert)
            logger.info(alert)

        # === Alert on Rare Record Types ===
        if query_type in rare_query_types:
            alert = f"[RARE TYPE] Suspicious record type ({query_type}) queried from {client_ip}"
            print(alert)
            logger.info(alert)

        # === Alert on Excessive Queries ===
        if query_counter[client_ip] > query_threshold:
            alert = f"[ALERT] 🚨 Excessive queries detected from {client_ip} (count: {query_counter[client_ip]})"
            print(alert)
            logger.info(alert)

        # === Alert on Zone Transfer Attempt ===
        if query_type == "AXFR":
            alert = f"[ALERT] 🚨 Zone transfer attempt (AXFR) from {client_ip} for {query_name}"
            print(alert)
            logger.info(alert)
            return  # AXFR not supported, don't reply

        # === Generate Fake DNS Response ===
        response = request.reply()
        if query_name in custom_responses and query_type == "A":
            response.add_answer(RR(query_name, QTYPE.A, rdata=custom_responses[query_name], ttl=300))
        elif query_type == "A":
            response.add_answer(RR(query_name, QTYPE.A, rdata=A("127.0.0.1"), ttl=300))
        elif query_type == "AAAA":
            response.add_answer(RR(query_name, QTYPE.AAAA, rdata=AAAA("::1"), ttl=300))
        elif query_type == "CNAME":
            response.add_answer(RR(query_name, QTYPE.CNAME, rdata=CNAME("fake.example.com"), ttl=300))
        elif query_type == "MX":
            response.add_answer(RR(query_name, QTYPE.MX, rdata=MX("mail.fake.com"), ttl=300))
        elif query_type == "TXT":
            response.add_answer(RR(query_name, QTYPE.TXT, rdata=TXT("This is a honeypot"), ttl=300))
        else:
            logger.info(f"Unsupported query type: {query_type}")

        # === Send DNS Response ===
        sock.sendto(response.pack(), self.client_address)

# === Start Server ===
def start_dns_honeypot(address='127.0.0.1', port=5353):
    print(f"[INFO] DNS Honeypot listening on {address}:{port}")
    with UDPServer((address, port), DNSHandler) as server:
        server.serve_forever()

#if __name__ == "__main__":
#   start_dns_honeypot()