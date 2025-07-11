from flask import Flask, render_template, request, redirect , url_for , flash
import logging
from logging import FileHandler 
from pathlib import Path

# Logging setup
base_dir = Path(__file__).parent.parent
log_path = base_dir / 'smart_honeypot_proj' / 'log_files' / 'http_audit.log'

logger = logging.getLogger('HTTPLogger')
logger.setLevel(logging.INFO)
handler = FileHandler(log_path)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

# Track failed login attempts
failed_logins = {}

def baseline_web_honeypot(input_username="admin", input_password="password"):
    app = Flask(__name__)
    app.secret_key = "honeypot123"  # Needed for flashing messages

    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']
        ip = request.remote_addr

        logger.info(f"Login attempt from {ip} - Username: {username}, Password: {password}")

        if username == input_username and password == input_password:
            logger.info(f"[SUCCESS] IP {ip} logged in successfully.")
            return redirect('/dashboard')
        else:
            failed_logins[ip] = failed_logins.get(ip, 0) + 1
            if failed_logins[ip] >= 3:
                logger.info(f"[ALERT] Multiple failed logins from IP {ip}")
            flash("❌ Invalid username or password. Please try again.")
            return redirect(url_for('index'))

    @app.route('/dashboard')
    def dashboard():
        ip = request.remote_addr
        logger.info(f"IP {ip} accessed /dashboard")
        return render_template('dashboard.html')

    # Fake sensitive paths
    @app.route('/backup.zip')
    def backup():
        ip = request.remote_addr
        logger.info(f"IP {ip} requested /backup.zip")
        return "Access Denied", 403

    @app.route('/etc/passwd')
    def etc_passwd():
        ip = request.remote_addr
        logger.info(f"IP {ip} tried directory traversal: /etc/passwd")
        return "root:x:0:0:root:/root:/bin/bash \n admin:x:1000:1000::/home/admin:/bin/bash \n ftpuser:x:1001:1001:ftp user:/home/ftp:/bin/false \n admin:password123 \n", 200

    @app.route('/wp-config.php')
    def config():
        ip = request.remote_addr
        logger.info(f"IP {ip} accessed /wp-config.php")
        return "<?php\n// FTP credentials\n$ftp_user='admin';\n$ftp_pass='password123'; ?>", 200

    return app

def run_app(port=5050, input_username="admin", input_password="password"):
    app = baseline_web_honeypot(input_username, input_password)
    app.run(debug=False, port=port, host="127.0.0.1")


#run_app()  