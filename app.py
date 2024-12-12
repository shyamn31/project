from flask import Flask, render_template, redirect, url_for, jsonify
from email_fetcher import connect_to_email, fetch_unread_emails, phishing_alerts
import schedule
import threading
import time
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv(dotenv_path='cred.env')

# Retrieve credentials
EMAIL_USERNAME = os.getenv('EMAIL_USERNAME')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_SERVER = "imap.gmail.com"

app = Flask(__name__)

# Dashboard route to show phishing alerts
@app.route('/')
def dashboard():
    print("Rendering dashboard with current phishing alerts.")  # Debugging line
    return render_template('dashboard.html', alerts=phishing_alerts)

# Route to manually trigger the email scan via a POST request
@app.route('/trigger_scan', methods=['POST'])
def trigger_scan():
    print("Manual scan triggered.")  # Debugging line
    try:
        mail = connect_to_email(EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_SERVER)
        if mail:
            fetch_unread_emails(mail)
            mail.logout()
            print("Manual scan completed successfully.")  # Debugging line
        return jsonify({"status": "success", "message": "Email scan completed successfully."})
    except Exception as e:
        print(f"Error during manual scan: {e}")  # Debugging line
        return jsonify({"status": "error", "message": str(e)})

# Schedule email scanning every 10 minutes
def scheduled_scan():
    print("Scheduled scan triggered.")  # Debugging line
    try:
        mail = connect_to_email(EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_SERVER)
        if mail:
            fetch_unread_emails(mail)
            mail.logout()
            print("Scheduled scan completed.")  # Debugging line
    except Exception as e:
        print(f"Error during scheduled scan: {e}")  # Debugging line

schedule.every(10).minutes.do(scheduled_scan)

# Background scheduler
def run_email_scanner():
    while True:
        schedule.run_pending()
        time.sleep(1)

# Start the Flask app and scheduler
if __name__ == '__main__':
    scanner_thread = threading.Thread(target=run_email_scanner)
    scanner_thread.start()
    app.run(debug=True)
