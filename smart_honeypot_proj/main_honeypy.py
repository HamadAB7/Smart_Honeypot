"""
# Import library dependencies.
import argparse
# Import project python file dependencies. This is the main file to interface with the honeypot with.  /// Importing files that we created (btw when we add an particular file/function you need to add this here too)
from ssh_honeypot import *
from web_honeypot import *
from dashboard_data_parser import *
from telnet_honeypot import *
from ftp_honeypot import *
from dns_honeypot import *
from smart_honeypot import * 
#from web_app import *       # You may need to add your own code for this , i think you need to be able to run also this from the main 

if __name__ == "__main__":      # This mean if we are executing from this file particularly , do the following , as we also created an instance of all the files we have 
    # Create parser and add arguments.
    parser = argparse.ArgumentParser()      
    parser.add_argument('-a','--address', type=str)              # You / should add another arguuments such as -h for help and so on , so it looks like more realistic (Note : the arguments is made by me , ya3ni i can change -p to be for password or whatever) . Adding options that you would like to have , type means we specify what type of parameter or argument will be inputed into this ( He did a str so this means he's accepting an string argument) and the last option is that we have to make this option optional or required and he made it required and so on for the rest (  required=True )....
    parser.add_argument('-p','--port', type=int)
    parser.add_argument('-u', '--username', type=str)       # He didnt say required so this option is optional , you can use either -u for short hand or --username for longer and so on 
    parser.add_argument('-w', '--password', type=str)
    parser.add_argument('-s', '--ssh', action="store_true")     # Store true means of this argument is supplied , store it as true otherwise if it's not supplied store it as false 
    parser.add_argument('-t', '--tarpit', action="store_true")
    parser.add_argument('-wh', '--http', action="store_true")
    parser.add_argument('-tt', '--telnet', action="store_true")  
    parser.add_argument('-f', '--ftp', action="store_true")
    parser.add_argument('-d', '--dns', action="store_true")
    # Example in argparse:
    parser.add_argument("--run_ai", action="store_true", help="Run the smart AI detection after services capture logs")

    args = parser.parse_args()      # Collect all the arguments above when provided and put them together 
    
    # Parse the arguments based on user-supplied argument.  For now we have 2 types of honeypot and we need to make it that we have a honeypot specified and handle of what happens 
    try:
        if args.ssh:        # Run the SSH based honeypot 
            print("[-] Running SSH Honeypot...")
            honeypot(args.address, args.port, args.username, args.password, args.tarpit)        # From the file ssh_honeypot , so that when this is provided by the user the honeypot works , same goes with the http thing and whatever you are adding  another services in the future 
        elif args.http:
            print('[-] Running HTTP Wordpress Honeypot...')
            if not args.username:
                args.username = "admin"
                print("[-] Running with default username of admin...")
            if not args.password:
                args.password = "password"
                print("[-] Running with default password of password...")
            print(f"Port: {args.port} Username: {args.username} Password: {args.password}")
            run_app(args.port, args.username, args.password)
        elif args.telnet : # "Add this when you make --telnet"
            print("[-] Running Telnet Honeypot...")
            start_telnet_honeypot(args.address, args.port)
        elif args.ftp :         # Do smt here 
            print("[-] Running FTP Honeypot...") 
            start_ftp_honeypot() 
        elif args.dns : 
            print("[-] Running DNS Honeypot...")
            start_dns_honeypot(args.address, args.port)
        else:
            print("[!] You can only choose SSH (-s) (--ssh) or HTTP (-h) (--http) or DNS (-d) (--dns) or FTP (-f) (--FTP) or TELNET (-tt) (--telnet) when running script.")      # For the time being , if nothing is called , print this 
        
        if args.run_ai:
            run_analysis()  # You wrap your code in a function inside the AI file

    except KeyboardInterrupt:       # If the user pressed a hot key such as ctrl+c this means he's exitting so do this . // You can also add smt like , if the user typed exit the honeypot should terminate .
        print("\nProgram exited.")
"""
# Import library dependencies.
import argparse
import threading 
# Import project python file dependencies. This is the main file to interface with the honeypot with.  /// Importing files that we created (btw when we add an particular file/function you need to add this here too)
from ssh_honeypot import *
from web_honeypot import *
from dashboard_data_parser import *
from telnet_honeypot import *
from ftp_honeypot import *
from dns_honeypot import *
from smart_honeypot import * 
#from web_app import *       # You may need to add your own code for this , i think you need to be able to run also this from the main 

if __name__ == "__main__":      # This mean if we are executing from this file particularly , do the following , as we also created an instance of all the files we have 
    # Create parser and add arguments.
    parser = argparse.ArgumentParser()      
    parser.add_argument('-a','--address', type=str)              # You / should add another arguuments such as -h for help and so on , so it looks like more realistic (Note : the arguments is made by me , ya3ni i can change -p to be for password or whatever) . Adding options that you would like to have , type means we specify what type of parameter or argument will be inputed into this ( He did a str so this means he's accepting an string argument) and the last option is that we have to make this option optional or required and he made it required and so on for the rest (  required=True )....
    parser.add_argument('-p','--port', type=int)
    parser.add_argument('-u', '--username', type=str)       # He didnt say required so this option is optional , you can use either -u for short hand or --username for longer and so on 
    parser.add_argument('-w', '--password', type=str)
    parser.add_argument('-s', '--ssh', action="store_true")     # Store true means of this argument is supplied , store it as true otherwise if it's not supplied store it as false 
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
    
    # Parse the arguments based on user-supplied argument.  For now we have 2 types of honeypot and we need to make it that we have a honeypot specified and handle of what happens 
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
