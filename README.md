![HONEPY-Logo](/smart_honeypot_proj/assets/images/Honeypot-logo-black-text.png)

A modular, AI-powered honeypot system with a graphical interface, capable of capturing, analyzing and adapting to malicious activity across SSH, HTTP, Telnet, DNS, and FTP. Includes anomaly detection, dynamic responses and a real-time dashboard. Written in Python.

# Install

**1) Clone repository.**
`git clone https://github.com/HamadAB7/Smart_Honeypot.git`

**2) Permissions.**
Move into `Smart_honeypot` folder.

Ensure `main_honeypy.py` has proper permissions. (`chmod 755 main_honeypy.py`)

**3) Keygen.**

Create a new folder `static`. 

`mkdir static`

Move into directory.

`cd static`

An RSA key must be generated for the SSH server host key. The SSH host key provides proper identification for the SSH server. Ensure the key is titled `server.key` and resides in the same relative directory to the main program.

`ssh-keygen -t rsa -b 2048 -f server.key`

# Usage

To provision a new instance of Smart_Honeypot, use the `main_honeypy.py` file. This is the main file to interface with for Smart_Honeypot. 

Smart_Honeypot requires a bind IP address (`-a`) and network port to listen on (`-p`). Use `0.0.0.0` to listen on all network interfaces. The protocol type must also be defined. There is many more options and commands that can be used.

```
-a / --address: Bind address.
-p / --port: Port.
-s / --ssh, -wh / --http: Declare honeypot type, -d / --dns, -tt / --telnet, -f / --ftp.
```

Example: `python3 main_honeypy.py -a 0.0.0.0 -p 22 --ssh`

💡 If Smart_Honeypot is set up to listen on a privileged port (22), the program must be run with `sudo` or root privileges. No other services should be using the specified port. 

If port 22 is being used as the listener, the default SSH port must be changed. Refer to Hostinger's "[How to Change the SSH Port](https://www.hostinger.com/tutorials/how-to-change-ssh-port-vps)" guide.

❗ To run with `sudo`, the `root` account must have access to all Python libraries used in this project (libraries defined in `requirements.txt`). Install by switching to the root account, then supply:

`root@my_host# pip install -r requirements`

This will install all the packages for the root user, but it will affect the global environment and isn't considered the "safest" way to do this.

**Optional Arguments**

A username (`-u`) and password (`-w`) can be specified to authenticate the SSH server. The default configuration will accept all usernames and passwords. Particular ports for different services can be specified each independently , such as http port (`--http_port`) or dns port (`--dns_port`) and so on for all five services, we did this to provide a way of running multiple services for different instances in the same time, this is called Multithreading .

```
-u / --username: Username.
-w / --password: Password.
-t / --tarpit: For SSH-based honeypots, -t can be used to trap sessions inside the shell, by sending a 'endless' SSH banner.
--http_port: Port number of the associated service, in this case here it's HTTP service.
--dns_port / --ftp_port / --telnet_port / --ssh_port 
```

Example: `python3 main_honeypy.py -a 0.0.0.0 -p 22 --ssh -u admin -w admin --tarpit`


# Logging Files

Smart_Honeypot has seven loggers configured. Loggers will route to either `cmd_audits.log`, `creds_audits.log` (for SSH), `http_audit.log` (for HTTP), `ftp_honeypot.log` (for FTP), `dns_honeypot.log` (for DNS), `telnet_honeypot.log` (for Telnet), `ai_behavioral.log` (for AI Model) log files for information capture, behavioral analysis and anomaly detection.

`cmd_audits.log`: Captures IP address, username, password, and all commands supplied.

`creds_audits.log`: Captures IP address, username, password, comma separated. Used to see how many hosts attempt to connect to ssh_honeypot.

`http_audit.log`: Captures IP address, username and password.

`ftp_honeypot.log`: Captures IP address, username, password, uploaded and downloaded files.

`dns_honeypot.log`: Captures timestamps, IP address, queried domain names and different DNS responses.

`telnet_honeypot.log`: Captures IP address, username, password and all commands supplied.

`ai_behavioral.log`: Captures IP address, timestamps, calculated severity and risk score.

The log files will be located in `../smart_honeypot_proj/log_files/..`

# Honeypot Types

This honeypot was written with modularity in mind to multiple honeypot types. As of right now there are five honeypot types supported.

## SSH
The project started out with only supported SSH. Use the following instructions above to provision an SSH-based honeypot which emulates a basic shell.

💡 `-t / --tarpit`: A tarpit is a security mechanism designed to slow down or delay the attempts of an attacker trying to brute-force login credentials. Leveraging Python's time module, a very long SSH-banner is sent to a connecting shell session. The only way to get out of the session is by closing the terminal. 

💡Integrated with the AI anomaly detection module, which assigns risk/severity scores based on observed behavior.

## HTTP
Using Python Flask as a basic template to provision a simple web service, Smart_Honeypot impersonates a default WordPress `wp-admin` login page. Username / password pairs are collected.

There are default credentials accepted, `admin` and `password123`, grant access to a monitored web page that simulates an access control panel with configuration settings, enabling us to observe attacker behavior and the commands they attempt. Username and password can be changed using the `-u / --username: Username.
-w / --password: Password` arguments.

The web-based honeypot runs on port 5000 by default. This can be changed using the `-p / --port` flag option.

💡Integrated with the dashboard for logging HTTP activity and displaying login attempts, Enhanced to simulate realistic HTTP responses and log session details.

## DNS
The DNS honeypot simulates a basic DNS resolver. That captures timestamp of each query, source IP address, queried domain names. The fake (or real) DNS responses sent back. Helps detect unauthorized or suspicious DNS queries and analyze patterns of potential data exfiltration or domain enumeration.

💡Results are logged and included in the dashboard and AI anomaly detection.

## FTP
The FTP honeypot emulates an FTP server. That captures IP address, login credentials, uploaded & downloaded files. Supports passive logging of file transfer commands and content. Integrated with the AI module to assess risk based on activity (e.g., many failed uploads, suspicious filenames).

## Telnet
The Telnet honeypot emulates a Telnet service similar to the SSH honeypot. Supports realistic prompts to keep attackers engaged. Integrated with AI anomaly detection and dashboard to evaluate the risk of Telnet session activities.

# Dashboard

Smart_Honeypot comes packaged with a `web_app.py` file. This can be run in a separate terminal session on localhost to view statistics such as top 10 IP addresses, usernames, passwords, commands, and all data in tabular format. As of right now, the dashboards do not dynamically update as new entries or information are added to the log files. The dashboard must be run every time to re-populate to the most up-to-date information.

Run `python3 web_app.py` on localhost. Default port for Python Dash is `8050`. `http://127.0.0.1:8050`. Go to your browser of choice to view dashboard metrics.

💡 The dashboard data includes a country code lookup that uses the IP address to determine the two-digit country code. To get the IP address, the [ipinfo() CleanTalk API](https://cleantalk.org/help/api-ip-info-country-code) is used. Due to rate limiting constraints, CleanTalk can only lookup 1000 IP addresses per 60 seconds. 
- By default, the country code lookup is set to `False`, as this will have impact on how long it takes to provision the honeypot (pandas has to pivot on dataframes, which takes time). Set the `COUNTRY` environment variable to `True` if you would like to get the country code lookup dashboard panel.
- If receiving rate limiting errors, change the `COUNTRY` environment variable in `public.env` to `False` again. 
- Dashboard Heatmap : Includes a heatmap that visualizes attack activity over time. Shows the distribution of threats by time of day and day of the week. Summarizes overall threat counts per day and per week, allowing you to quickly identify peak attack periods.

Smart_Honeypot leverages Python Dash to populate the bar charts, Dash Bootstrap Components for dark-theme and style of charts, and Pandas for data parsing.

<img src="/smart_honeypot_proj/assets/images/Dashboard.png" alt="Dashboard" width="600"/>

# Smart Honeypot ( AI Model )

The Smart Honeypot incorporates an embedded AI module designed to enhance traditional honeypot functionality with behavioral analysis, anomaly detection, and risk scoring, enabling defenders to prioritize threats more effectively and detect novel attacker behaviors in real-time. By leveraging machine learning, the honeypot does not only record attacker activity but also analyzes patterns to distinguish between benign, expected interactions and potentially malicious or anomalous behavior.

💡 To run the model , navigate to the main_honeypot and run `python ./main_honeypy.py -a <ip_address> --run_ai`. You will find different information based on three files , `block_list.txt` that shows recommended blocked addresses , `ai_behavioral.log` shows the risk score and severity of different types of attacks applied inside the monitored environment and finally the `high_risk_anomalies.csv`  is a report generated by the AI model as part of its anomaly detection and risk scoring process. It serves as a human-readable export of all sessions the AI flagged as high-risk or anomalous, making it easy to review, share, or archive outside of the dashboard or log files.
- Detect unusual attacker behavior that deviates from previously observed patterns.
- Calculate a severity score for each session, helping prioritize responses.
- Provide defenders with actionable intelligence beyond raw logs.
- The AI model is implemented using the Isolation Forest algorithm, a popular unsupervised anomaly detection technique. Isolation Forest works by building random trees that partition the data — anomalous points are isolated faster (with fewer splits) than normal points. This makes it highly effective for identifying outliers in high-dimensional datasets, such as attacker behavior logs.

# Multithreading

This section of code is responsible for starting multiple honeypot services simultaneously, each listening on its own port (SSH, HTTP, DNS, Telnet, FTP). It achieves this by using Python’s threading module, which allows multiple tasks (threads) to run “in parallel” within the same process. Each honeypot service runs in its own thread, which allows the main program to keep running while each service listens for connections independently. With threads, all services start “simultaneously” and can handle incoming connections at the same time.

💡 The Multithreading feature is implemented in main_honeypot.py, enabling multiple honeypot services to run concurrently on separate ports. An example of running the functionality `python ./main_honeypy.py -s --ssh_port 2223 -wh --http_port 5050 -d --dns_port 5353 -a 127.0.0.1 -u username -w 12345` this will run the SSH, HTTP, DNS services simultaneously with the specified port for each service and providing an username and a password for the SSH emulated shell .

# VPS Hosting (General Tips)

To host on VPS, follow the general tips.

To gather logging information, it's advised to use a Virtual Private Server (VPS). VPS's are cloud-based hosts with Internet access. This provides a safe, isolated way to gather real-time information without having to configure and isolate infrastructure on your home network.

A majority of VPS hosting providers will provide a Virtual Firewall where you can open ports. Ensure to open ports used by Smart_Honeypot.
- `Port 80`, `Port 5000`, `Port 2223` (Whichever port you configure to listen on real SSH connection), `Port 8050`. 

When working on Linux-based distributions, also open the ports with IP Tables or Unfiltered Firewall (UFW). 
- `ufw enable`
- `ufw allow [port]`

# Running in Background With Systemd

To run Smart_Honeypot in the background, you can use Systemd for popular Linux-based distributions.

There is a template included under the systemd folder in this repo.

Supply the required arguments after the `main_honeypy.py` to run with your desired configuration. Use your favorite text editor to change the configuration.
- `ExecStart=/usr/bin/python3 /main_honeypy.py -a 127.0.0.1 -p 22 --ssh`

Copy `honeypy.service` template file into `/etc/systemd/system`. `cp honeypy.service /etc/systemd/system`.

Reload systemd with the new configuration added, `systemctl daemon-reload`.

Enable the `honeypy.service` file with `systemctl enable honeypy.service`.  

Start the `honepy.service` file with `systemctl start honepy.service`.

# Helpful Resources

Resources and guides used while developing project.

- https://securehoney.net/blog/how-to-build-an-ssh-honeypot-in-python-and-docker-part-1.html 
- https://medium.com/@abdulsamie488/deceptive-defense-building-a-python-honeypot-to-thwart-cyber-attackers-2a9d2ced2760
- https://gist.github.com/cschwede/3e2c025408ab4af531651098331cce45
- https://www.hostinger.com/tutorials/how-to-change-ssh-port-vps
