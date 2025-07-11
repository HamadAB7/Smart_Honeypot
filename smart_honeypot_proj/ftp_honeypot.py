import os
import time
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer

# FTP Honeypot Configuration
HOST = '0.0.0.0'
PORT = 2121
LOG_FILE = 'log_files/ftp_honeypot.log'

# Set up fake honeypot file system
honeypot_root = "/tmp/ftp_honeypot"
os.makedirs(honeypot_root, exist_ok=True)
subdirs = ["confidential", "configs", "uploads", "logs"]
for sub in subdirs:
    os.makedirs(os.path.join(honeypot_root, sub), exist_ok=True)

# Create dummy files
with open(os.path.join(honeypot_root, "confidential", "secret_plans.txt"), "w") as f:
    f.write("You’ve reached sensitive project data. \n \r[!] Security Warning: \n \rPlease patch the HTTP service. Directory traversal is still unpatched! \n")
with open(os.path.join(honeypot_root, "configs", "db_config.conf"), "w") as f:
    f.write("db_user=admin\ndb_pass=toor\n")

# Custom FTP Handler for logging activity
class HoneypotFTPHandler(FTPHandler):
    def on_connect(self):
        ip = self.remote_ip
        print(f"[INFO] Connection from {ip}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip} connected.\n")

    def on_login(self, username):
        ip = self.remote_ip
        password = self.password
        print(f"[INFO] Login attempt - IP: {ip}, Username: {username}, Password: {password}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip}, Username: {username}, Password: {password}\n")

    def on_file_received(self, file):
        ip = self.remote_ip
        filename = os.path.basename(file)
        size = os.path.getsize(file)
        print(f"[INFO] File received from {ip}: {filename} ({size} bytes)")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip} uploaded file: {filename} ({size} bytes)\n")

    def on_file_sent(self, file):
        ip = self.remote_ip
        filename = os.path.basename(file)
        print(f"[INFO] File downloaded by {ip}: {filename}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip} downloaded file: {filename}\n")

    def on_incomplete_command(self, cmd, arg, respcode, respstr):
        ip = self.remote_ip
        full_cmd = f"{cmd} {arg}" if arg else cmd
        print(f"[INFO] Command from {ip}: {full_cmd}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip} sent command: {full_cmd}\n")

    def on_disconnect(self):
        ip = self.remote_ip
        print(f"[INFO] Disconnection from {ip}")
        with open(LOG_FILE, 'a') as log:
            log.write(f"{time.ctime()} - IP: {ip} disconnected.\n")

def start_ftp_honeypot():
    # Set up dummy credentials
    authorizer = DummyAuthorizer()
    authorizer.add_user("admin", "password123", honeypot_root, perm="elradfmw")  # full permissions
    authorizer.add_anonymous(honeypot_root, perm="elr")  # Anonymous users read-only

    # Assign the custom handler
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.banner = "220 Welcome to the Honeypot FTP Server."

    # Start FTP Server
    server = FTPServer((HOST, PORT), handler)
    print(f"[INFO] FTP Honeypot listening on {HOST}:{PORT}")
    server.serve_forever()

#if __name__ == "__main__":
#   start_ftp_honeypot()