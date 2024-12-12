import imaplib
import email
from email.header import decode_header
import re
import string
from phishing_detection import detect_phishing
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv(dotenv_path='cred.env')

# Get credentials from environment variables
EMAIL_USERNAME = os.getenv('EMAIL_USERNAME')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
EMAIL_SERVER = "imap.gmail.com"  # or another email provider's IMAP server

# Initialize the phishing alerts list
phishing_alerts = []

# Function to connect to the email server
def connect_to_email(username, password, server="imap.gmail.com"):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(username, password)
        mail.select("inbox")  # Select inbox
        print("Connected to email successfully.")
        return mail
    except Exception as e:
        print(f"Error connecting to email: {e}")
        return None

# Function to fetch unread emails
def fetch_unread_emails(mail):
    try:
        status, messages = mail.search(None, 'UNSEEN')
        if status == "OK":
            email_ids = messages[0].split()
            print(f"Unread emails found: {len(email_ids)}")
            for email_id in email_ids:
                status, msg_data = mail.fetch(email_id, "(RFC822)")
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        msg = email.message_from_bytes(response_part[1])
                        process_email(msg)
        else:
            print("No new unread emails.")
    except Exception as e:
        print(f"Error fetching emails: {e}")

# Function to process each email
def process_email(msg):
    subject, encoding = decode_header(msg["Subject"])[0]
    if isinstance(subject, bytes):
        subject = subject.decode(encoding or "utf-8")
    print(f"Processing email with subject: {subject}")

    email_body = ""
    attachments = []

    # Parse email parts
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            if content_type == "text/plain" and "attachment" not in content_disposition:
                email_body = part.get_payload(decode=True).decode("utf-8", errors="ignore")
                print(f"Email body detected: {email_body}")
            elif "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    attachments.append(filename)
                    print(f"Attachment found: {filename}")
    else:
        email_body = msg.get_payload(decode=True).decode("utf-8", errors="ignore")
        print(f"Single-part email body detected: {email_body}")

    # Run phishing detection and add result to phishing_alerts if phishing is detected
    phishing_flag, details = detect_phishing(email_body, attachments)
    if phishing_flag:
        phishing_alerts.append({"subject": subject, "details": details})
        print("Phishing detected and added to alerts.")
    else:
        print("No phishing detected in this email.")

# Initialize mail connection
mail = connect_to_email(EMAIL_USERNAME, EMAIL_PASSWORD, EMAIL_SERVER)

# Fetch unread emails if the connection was successful
if mail:
    fetch_unread_emails(mail)
else:
    print("Failed to connect to the email server.")
