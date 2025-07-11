# Import library dependencies.
import logging        
from logging.handlers import RotatingFileHandler    
import paramiko   
import threading
import socket
import time
from pathlib import Path
# Constants.   
SSH_BANNER = "SSH-2.0-MySSHServer_1.0"          

# Get base directory of where user is running honeypy from.
base_dir = Path(__file__).parent.parent
# Source creds_audits.log & cmd_audits.log file path.
server_key = base_dir / 'smart_honeypot_proj' / 'static' / 'server.key'
#This is for the brute forcing detection 
brute_force_tracker = {}
MAX_ATTEMPTS = 5  # You can tune this
creds_audits_log_local_file_path = base_dir / 'smart_honeypot_proj' / 'log_files' / 'creds_audits.log'          
cmd_audits_log_local_file_path = base_dir / 'smart_honeypot_proj' / 'log_files' / 'cmd_audits.log'

# SSH Server Host Key.  
host_key = paramiko.RSAKey(filename=server_key,password="")

# Logging Format.      
logging_format = logging.Formatter('%(message)s')  

# Funnel (catch all) Logger. (Loggers and Logger Files) 
funnel_logger = logging.getLogger('FunnelLogger')     
funnel_logger.setLevel(logging.INFO)       
funnel_handler = logging.FileHandler(cmd_audits_log_local_file_path)    
funnel_handler.setFormatter(logging_format)  
funnel_logger.addHandler(funnel_handler)    
if not funnel_logger.handlers:
    funnel_logger.addHandler(funnel_handler)

# Credentials Logger.
creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = logging.FileHandler(creds_audits_log_local_file_path)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)
if not creds_logger.handlers:
    creds_logger.addHandler(creds_handler)
 
# SSH Server Class. This establishes the options for the SSH server.
class Server(paramiko.ServerInterface):     
    # Defining several functions as this is going to provide the setting for the SSH server 
    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()     
        self.client_ip = client_ip
        self.input_username = input_username        
        self.input_password = input_password

    def check_channel_request(self, kind, chanid):      
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED     
    
    def get_allowed_auths(self, username):  
        return "password"

    def check_auth_password(self, username, password):
        client_ip = self.client_ip

        # Log every attempt
        funnel_logger.info(f'Client {client_ip} attempted connection with username: {username}, password: {password}')
        creds_logger.info(f'{client_ip}, {username}, {password}')

        # Brute-force tracking
        if client_ip not in brute_force_tracker:
            brute_force_tracker[client_ip] = 0

        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                brute_force_tracker[client_ip] += 1
                if brute_force_tracker[client_ip] >= MAX_ATTEMPTS:
                    funnel_logger.warning(f'Brute-force detected from {client_ip} — blocking further attempts.')
                    return paramiko.AUTH_FAILED
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):   
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):        
        return True

    def check_channel_exec_request(self, channel, command):          
        command = str(command)
        return True

def setup_logger(name, log_file, level=logging.INFO):
    log_path = Path("log_files") / log_file
    log_path.parent.mkdir(parents=True, exist_ok=True)

    handler = logging.FileHandler(log_path)
    formatter = logging.Formatter('%(asctime)s - %(message)s')
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)

    return logger

# Instantiate your loggers
creds_logger = setup_logger("creds_logger", "creds_audits.log")
cmd_logger = setup_logger("cmd_logger", "cmd_audits.log")

def emulated_shell(channel, client_ip):
    channel.send(b"corporate-jumpbox2$ ")
    command = b""
    current_dir = "/home/admin"

    fake_files = {
        "/home/admin": ["file1.txt", "notes.txt", "secrets"],
        "/etc": ["passwd", "shadow", "hosts"],
        "/var/log": ["auth.log", "syslog"],
    }

    fake_file_contents = {
        "file1.txt": b"This is a sample honeypot file.",
        "notes.txt": b"\n\nHi Ahmed, \n \rRemember, we moved the admin panel for the web app behind a DNS-based subdomain. \n \rYou can query it using: \n \rdig wp-admin-panel.localhost @127.0.0.1 -p 5353 \n \rAlso, dont forget: The file /etc/passwd contains legacy login credentials. \n \rWe didnt encrypt that yet. \n\n \rCheers, \n \rDevOps \n\n",
        "secrets": b"Project Zephyr Password: hunter2",
        "passwd": b"root:x:0:0:root:/root:/bin/bash\n \radmin:x:1000:1000:Admin:/home/admin:/bin/bash",
    }

    while True:
        char = channel.recv(1)

        # Handle backspace
        if char == b"\x7f" and len(command) > 0:
            command = command[:-1]
            channel.send(b"\b \b")
            continue

        # Echo character
        channel.send(char)

        # If connection drops
        if not char:
            channel.close()
            break

        command += char

        # If user hits Enter
        if char == b"\r":
            stripped_cmd = command.strip().decode()
            response = b""

            if stripped_cmd == "":
                # Empty input, just move to next prompt
                channel.send(b"\r\ncorporate-jumpbox2$ ")
                command = b""
                continue

            if stripped_cmd == "exit":
                channel.send(b"\r\nGoodbye!\r\n")
                channel.close()
                break

            elif stripped_cmd == "pwd":
                response = f"{current_dir}".encode()

            elif stripped_cmd == "ls":
                listing = "  ".join(fake_files.get(current_dir, []))
                response = listing.encode()

            elif stripped_cmd.startswith("cd "):
                target = stripped_cmd[3:].strip()
                # Normalize relative paths like "./folder"
                if not target.startswith("/"):
                    target = f"{current_dir}/{target}"
                # Allow changing to existing fake directories
                if target in fake_files:
                    current_dir = target
                    response = b""
                # If the directory was just created via mkdir but not yet tracked
                elif target in [f"{current_dir}/{d}" for d in fake_files.get(current_dir, [])]:
                    current_dir = target
                    fake_files[current_dir] = []
                    response = b""
                else:
                    response = f"bash: cd: {target}: No such file or directory".encode()
                        
            elif stripped_cmd.startswith("cat "):
                filename = stripped_cmd[4:].strip()
                response = fake_file_contents.get(filename, f"cat: {filename}: No such file or permission denied".encode())

            elif stripped_cmd.startswith("mkdir "):
                new_dir = stripped_cmd[6:].strip()
                if new_dir in fake_files.get(current_dir, []):
                    response = f"mkdir: cannot create directory ‘{new_dir}’: File exists".encode()
                else:
                    fake_files[current_dir].append(new_dir)
                    fake_files[f"{current_dir}/{new_dir}"] = []
                    response = b""

            elif stripped_cmd == "whoami":
                response = b"corpuser1"

            elif stripped_cmd == "ps":
                response = b"PID TTY          TIME CMD\n1234 pts/0    00:00:01 bash\n1235 pts/0    00:00:00 ps"

            elif stripped_cmd == "netstat":
                response = b"Proto Recv-Q Send-Q Local Address           Foreign Address         State\nTCP   0      0    0.0.0.0:22           0.0.0.0:*               LISTEN"

            elif stripped_cmd == "uname -a":
                response = b"Linux honeypot-server 5.15.0-50-generic #56-Ubuntu SMP x86_64 GNU/Linux"

            elif stripped_cmd in ["clear", "cls"]:
                response = b"\r\n" * 20

            else:
                response = f"bash: {stripped_cmd}: command not found".encode()

            # Log the command
            funnel_logger.info(f'Command {stripped_cmd.encode()}' + "executed by " f'{client_ip}')

            # Send response and prompt
            channel.send(b"\r\n" + response + b"\r\ncorporate-jumpbox2$ ")
            command = b""


def client_handle(client, addr, username, password, tarpit=False):      
    client_ip = addr[0]  
    print(f"{client_ip} connected to server.")
    try:
    
        # Initlizes a Transport object using the socket connection from client.
        transport = paramiko.Transport(client)  # initalize an transport object , handling a new ssh session 
        transport.local_version = SSH_BANNER        # Set the ssh banner version for this transport object  

        # Creates an instance of the SSH server, adds the host key to prove its identity, starts SSH server.
        server = Server(client_ip=client_ip, input_username=username, input_password=password)     
        transport.add_server_key(host_key)     
        transport.start_server(server=server)
        channel = transport.accept(100)    

        if channel is None:
            print("No channel was opened.")

        standard_banner = "Welcome to Ubuntu 22.04 LTS ( Service 22.04 )!\r\n\r\n"      
        
        try:
            # Endless Banner: If tarpit option is passed, then send 'endless' ssh banner.
            if tarpit:
                endless_banner = standard_banner * 100
                for char in endless_banner:
                    channel.send(char)
                    time.sleep(8)
            # Standard Banner: Send generic welcome banner to impersonate server.
            else:
                channel.send(standard_banner)
            # Send channel connection to emulated shell for interpretation.
            emulated_shell(channel, client_ip=client_ip)

        except Exception as error:
            print(error)
    # Generic catch all exception error code.
    except Exception as error:
        print(error)
        print("!!! Exception !!!")
    
    # Once session has completed, close the transport connection. Either if it was successfully or not  
    finally:
        try:
            transport.close()
        except Exception as error :  
            print(error)
            print(" !! Error !! ")
         
        client.close()

def honeypot(address, port, username, password, tarpit=False):  
    
    # Open a new socket using TCP, bind to port.    
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     
    socks.bind((address, port))

    # Can handle 100 concurrent connections.
    socks.listen(100)
    print(f"SSH server is listening on port {port}.")     

    while True: 
        try:
            # Accept connection from client and address.
            client, addr = socks.accept()
            # Start a new thread to handle the client connection.
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password, tarpit))       
            ssh_honeypot_thread.start()

        except Exception as error:
            # Generic catch all exception error code.
            print("!!! Exception - Could not open new client connection !!!")
            print(error)

#honeypot('127.0.0.1',2223,'username','12345')
