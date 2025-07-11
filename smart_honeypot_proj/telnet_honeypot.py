from pathlib import Path
import socket
import threading
import logging

# === Setup ===
log_dir = Path("log_files")
log_dir.mkdir(exist_ok=True)
log_file = log_dir / "telnet_honeypot.log"

logging.basicConfig(
    filename=log_file,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# === Fake File System ===
fake_filesystem = {
    "/home/iot": ["notes.txt", "passwd", "flag.txt"],
    "/home/iot/logs": ["access.log", "syslog"],
    "/etc": ["shadow", "config"],
}
file_contents = {
    "notes.txt": "TODO: Monitor telnet logins.\n",
    "passwd": "admin:x:0:0:Admin:/home/admin:/bin/sh\n",
    "shadow": "root:$6$abc$fakehash:::",
    "flag.txt": "CTF{telnet_attack_captured}",
    "access.log": "Suspicious login from 192.168.1.55\n",
    "config": "device_mode=prod\nlog_level=debug\n",
    "syslog": "System rebooted. Kernel version 3.10.0\n"
}

# === AI Alerts Keywords ===
sensitive_keywords = ["passwd", "shadow", "flag", "config", "cd /etc", "cat"]

# === Brute Force Tracking ===
failed_logins = {}

# === Handle Client Session ===
def handle_client(client_socket, client_address):
    ip = client_address[0]
    logging.info(f"Connection from {ip}")
    failed_logins[ip] = failed_logins.get(ip, 0)

    try:
        # --- Login Interaction ---
        client_socket.sendall(b"Welcome to Telnet Service\nlogin: ")
        username = client_socket.recv(1024).strip().decode()
        client_socket.sendall(b"Password: ")
        password = client_socket.recv(1024).strip().decode()

        VALID_USERNAME = "admin"
        VALID_PASSWORD = "password123"

        if username != VALID_USERNAME or password != VALID_PASSWORD:
            failed_logins[ip] += 1
            logging.warning(f"[FAILED LOGIN] IP: {ip}, Username: {username}, Password: {password} (Attempt #{failed_logins[ip]})")

            if failed_logins[ip] >= 3:
                logging.warning(f"[BRUTE FORCE ALERT] Too many failed logins from {ip}")
                client_socket.sendall(b"Too many failed attempts. Connection closed.\n")
                client_socket.close()
                return
            else:
                client_socket.sendall(b"Login failed. Try again later.\n")
                client_socket.close()
                return

        failed_logins[ip] = 0  # Reset on success
        logging.info(f"[LOGIN SUCCESS] IP: {ip}, Username: {username}, Password: {password}")
        client_socket.sendall(b"Login successful.\nType 'help' to see available commands.\n\n")

        # --- Simulated Shell ---
        current_dir = "/home/iot"
        command_count = 0
        alert_triggered = False

        while True:
            prompt = f"{current_dir}$ ".encode()
            client_socket.sendall(prompt)
            command = client_socket.recv(1024).strip().decode()
            if not command:
                continue

            command_count += 1
            logging.info(f"{ip} executed: {command}")

            # Detection logic
            if any(keyword in command for keyword in sensitive_keywords) or command_count > 6:
                if not alert_triggered:
                    logging.info(f"[ALERT] Suspicious behavior from {ip}")
                    client_socket.sendall(b"[!] Intrusion Detected: Admin has been notified.\n")
                    alert_triggered = True

            # === Command Handling ===
            if command == "exit":
                client_socket.sendall(b"Goodbye!\n")
                break

            elif command == "help":
                help_text = (
                    "Commands: ls, cd, pwd, whoami, cat [file], mkdir [dir], ps, netstat, uname -a, exit\n"
                )
                client_socket.sendall(help_text.encode())

            elif command == "pwd":
                client_socket.sendall(f"{current_dir}\n".encode())

            elif command == "ls":
                files = fake_filesystem.get(current_dir, [])
                output = "\n".join(files) + "\n"
                client_socket.sendall(output.encode())

            elif command.startswith("cd "):
                path = command.split(" ", 1)[1]
                if path in fake_filesystem:
                    current_dir = path
                else:
                    client_socket.sendall(f"cd: {path}: No such file or directory\n".encode())

            elif command.startswith("cat "):
                file = command.split(" ", 1)[1]
                if file in file_contents:
                    client_socket.sendall(f"{file_contents[file]}\n".encode())
                else:
                    client_socket.sendall(f"cat: {file}: No such file or permission denied\n".encode())

            elif command.startswith("mkdir "):
                dir_name = command.split(" ", 1)[1]
                if dir_name not in fake_filesystem.get(current_dir, []):
                    fake_filesystem.setdefault(current_dir, []).append(dir_name)
                    client_socket.sendall(b"Directory created.\n")
                else:
                    client_socket.sendall(b"mkdir: File exists.\n")

            elif command == "whoami":
                client_socket.sendall(b"iot_user\n")

            elif command == "ps":
                client_socket.sendall(b"PID TTY          TIME CMD\n1000 tty1    00:00:00 bash\n")

            elif command == "netstat":
                client_socket.sendall(b"tcp        0      0 0.0.0.0:23           0.0.0.0:*               LISTEN\n")

            elif command == "uname -a":
                client_socket.sendall(b"Linux honeypot 5.4.0 iot x86_64 GNU/Linux\n")

            else:
                client_socket.sendall(f"{command}: command not found\n".encode())

    except Exception as e:
        logging.error(f"[ERROR] With {ip}: {str(e)}")
    finally:
        client_socket.close()

# === Start the Honeypot ===
def start_telnet_honeypot(host='0.0.0.0', port=2323):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[INFO] Telnet Honeypot running on {host}:{port}")
    try:
        while True:
            client, addr = server.accept()
            threading.Thread(target=handle_client, args=(client, addr)).start()
    except KeyboardInterrupt:
        print("[INFO] Stopping honeypot...")
        server.close()

# Run
# start_telnet_honeypot()