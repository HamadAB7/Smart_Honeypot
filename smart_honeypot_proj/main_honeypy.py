# Import library dependencies.
import argparse
import threading 
# Import project python file dependencies. This is the main file to interface with the honeypot with.
from ssh_honeypot import *
from web_honeypot import *
from dashboard_data_parser import *
from telnet_honeypot import *
from ftp_honeypot import *
from dns_honeypot import *
from smart_honeypot import * 

if __name__ == "__main__":     
    # Create parser and add arguments.
    parser = argparse.ArgumentParser()      
    parser.add_argument('-a','--address', type=str)
    parser.add_argument('-p','--port', type=int)
    parser.add_argument('-u', '--username', type=str)
    parser.add_argument('-w', '--password', type=str)
    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-t', '--tarpit', action="store_true")
    parser.add_argument('-wh', '--http', action="store_true")
    parser.add_argument('-tt', '--telnet', action="store_true")  
    parser.add_argument('-f', '--ftp', action="store_true")
    parser.add_argument('-d', '--dns', action="store_true")
    # Example in argparse:
    parser.add_argument("--run_ai", action="store_true", help="Run the smart AI detection after services capture logs")
    parser.add_argument('--ssh_port', type=int, help="Port for SSH Honeypot")
    parser.add_argument('--http_port', type=int, help="Port for HTTP Honeypot")
    parser.add_argument('--dns_port', type=int, help="Port for DNS Honeypot")
    parser.add_argument('--telnet_port', type=int, help="Port for Telnet Honeypot")
    parser.add_argument('--ftp_port', type=int, help="Port for FTP Honeypot")
    args = parser.parse_args()      # Collect all the arguments above when provided and put them together 
    
    # Parse the arguments based on user-supplied argument. 
    try:
        threads = []

        if args.ssh:
            ssh_port = args.ssh_port or 2223
            print(f"[-] Starting SSH Honeypot on port {ssh_port}...")
            t = threading.Thread(target=honeypot, args=(args.address, ssh_port, args.username, args.password, args.tarpit))
            threads.append(t)

        if args.http:
            http_port = args.http_port or 5050
            print(f"[-] Starting HTTP Honeypot on port {http_port}...")
            if not args.username:
                args.username = "admin"
            if not args.password:
                args.password = "password"
            t = threading.Thread(target=run_app, args=(http_port, args.username, args.password))
            threads.append(t)

        if args.dns:
            dns_port = args.dns_port or 5353
            print(f"[-] Starting DNS Honeypot on port {dns_port}...")
            t = threading.Thread(target=start_dns_honeypot, args=(args.address, dns_port))
            threads.append(t)

        if args.telnet:
            telnet_port = args.telnet_port or 2323
            print(f"[-] Starting Telnet Honeypot on port {telnet_port}...")
            t = threading.Thread(target=start_telnet_honeypot, args=(args.address, telnet_port))
            threads.append(t)

        if args.ftp:
            ftp_port = args.ftp_port or 2121
            print(f"[-] Starting FTP Honeypot on port {ftp_port}...")
            t = threading.Thread(target=start_ftp_honeypot)  # If this function supports custom ports, add them
            threads.append(t)
        
        if args.run_ai:
                    run_analysis()

        if not (args.ssh or args.http or args.dns or args.telnet or args.ftp or args.run_ai):
            print("[!] You must specify at least one honeypot service to run.")
            exit()
            
        # Start all services
        for t in threads:
            t.start()

        for t in threads:
            t.join()
        
    except KeyboardInterrupt:
        print("\n[!] Program exited.")
