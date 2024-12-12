from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv(load_dotenv(dotenv_path='cred.env'))

# Test print to verify variables are loaded
print("Email Username:", os.getenv('EMAIL_USERNAME'))
print("Email Password:", os.getenv('EMAIL_PASSWORD'))
