import re
import pickle
import string 
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# Path to save/load trained model and vectorizer
MODEL_PATH = "rf_classifier.pkl"
VECTORIZER_PATH = "tfidf_vectorizer.pkl"

# Preprocess email content for analysis
def preprocess_email(text):
    text = text.lower()
    text = re.sub(r"http\\S+|www\\S+|https\\S+", '', text, flags=re.MULTILINE)
    text = re.sub(r'\S+@\S+', '', text)
    text = re.sub(r'\d+', '', text)
    text = text.translate(str.maketrans('', '', string.punctuation))
    text = re.sub(r'\s+', ' ', text).strip()
    return text

# Sample training data
emails = [
    "Please verify your account at http://phishingsite.com",
    "Your order has shipped! Track it here: http://retailersite.com",
    "Update your banking info at http://securebanking.com",
    "Special offer just for you, click here",
    "Your account has been locked. Verify here",
    "Welcome to our platform! Start shopping now"
]
labels = [1, 0, 1, 0, 1, 0]  # 1 = phishing, 0 = legitimate


def train_model():
    # Preprocess the emails
    preprocessed_emails = [preprocess_email(email) for email in emails]

    # Initialize the TF-IDF Vectorizer and transform the data
    vectorizer = TfidfVectorizer(stop_words='english')
    X = vectorizer.fit_transform(preprocessed_emails)

    # Train the RandomForestClassifier
    X_train, X_test, y_train, y_test = train_test_split(X, labels, test_size=0.2, random_state=42)
    clf = RandomForestClassifier()
    clf.fit(X_train, y_train)

    # Evaluate the model
    predictions = clf.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Training Accuracy: {accuracy:.2f}")

    # Save the trained model and vectorizer
    with open(MODEL_PATH, 'wb') as model_file:
        pickle.dump(clf, model_file)
    with open(VECTORIZER_PATH, 'wb') as vectorizer_file:
        pickle.dump(vectorizer, vectorizer_file)
    print("Model and vectorizer saved.")

# Load model and vectorizer
def load_model():
    with open(MODEL_PATH, 'rb') as model_file:
        clf = pickle.load(model_file)
    with open(VECTORIZER_PATH, 'rb') as vectorizer_file:
        vectorizer = pickle.load(vectorizer_file)
    return clf, vectorizer

# Phishing detection function using the trained model
def detect_phishing_email_content(email_text):
    clf, vectorizer = load_model()
    preprocessed_text = preprocess_email(email_text)
    email_vector = vectorizer.transform([preprocessed_text])
    content_flag = clf.predict(email_vector)[0]  # 1 = phishing, 0 = legitimate
    return content_flag
# Function to extract URLs from email content
def extract_urls(text):
    # Regular expression to identify URLs
    url_pattern = r'(https?://\S+|www\.\S+)'
    return re.findall(url_pattern, text)

# Function to check if a URL is suspicious
def is_suspicious_url(url):
    # List of common phishing keywords to look for in URLs
    phishing_keywords = ['login', 'verify', 'account', 'secure', 'update']
    # Check if any keyword is in the URL
    if any(keyword in url for keyword in phishing_keywords):
        return True
    # Check if the URL is an IP address (often used in phishing attacks)
    ip_pattern = r'([0-9]{1,3}\.){3}[0-9]{1,3}'
    return bool(re.search(ip_pattern, url))

# Function to check if an attachment file type is suspicious
def is_suspicious_attachment(filename):
    # List of potentially dangerous file extensions
    suspicious_extensions = ['.exe', '.scr', '.vbs', '.js']
    return any(filename.endswith(ext) for ext in suspicious_extensions)
# Call this once to train and save the model
if __name__ == "__main__":
    train_model()
def detect_phishing(email_text, attachments):
    details = []

    # Detect phishing in email content
    content_flag = detect_phishing_email_content(email_text)
    if content_flag:
        details.append("Suspicious email content detected.")

    # Detect phishing in URLs
    urls = extract_urls(email_text)
    for url in urls:
        if is_suspicious_url(url):
            details.append(f"Suspicious URL detected: {url}")
            break

    # Check attachments
    for attachment in attachments:
        if is_suspicious_attachment(attachment):
            details.append(f"Suspicious attachment detected: {attachment}")
            break

    # Return results
    if details:
        return True, details
    else:
        return False, None