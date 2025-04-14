import streamlit as st
import hashlib
import json
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# Constants
MAX_ATTEMPTS = 3
LOCKOUT_DURATION = 300  # 5 minutes in seconds
DATA_FILE = "encrypted_data.json"

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_attempt_time' not in st.session_state:
    st.session_state.last_attempt_time = None
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False

# Generate or load encryption key
def get_encryption_key():
    if 'encryption_key' not in st.session_state:
        key = Fernet.generate_key()
        st.session_state.encryption_key = key
    return st.session_state.encryption_key

# Initialize cipher
cipher = Fernet(get_encryption_key())

# Load stored data
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            return json.load(f)
    return {}

# Save data to file
def save_data(data):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f)

# Initialize stored data
stored_data = load_data()

# Enhanced passkey hashing using PBKDF2
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

# Encrypt data
def encrypt_data(text, passkey):
    try:
        salt = os.urandom(16)
        hashed_key, salt = hash_passkey(passkey, salt)
        encrypted_text = cipher.encrypt(text.encode()).decode()
        return encrypted_text, hashed_key.decode(), salt.hex()
    except Exception as e:
        st.error(f"Error during encryption: {str(e)}")
        return None, None, None

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        # Check if user is locked out
        if st.session_state.last_attempt_time:
            time_since_last_attempt = (datetime.now() - st.session_state.last_attempt_time).total_seconds()
            if time_since_last_attempt < LOCKOUT_DURATION and st.session_state.failed_attempts >= MAX_ATTEMPTS:
                st.error(f"🔒 Account locked. Please try again in {int(LOCKOUT_DURATION - time_since_last_attempt)} seconds.")
                return None
        
        # Find matching encrypted text
        for key, value in stored_data.items():
            if value['encrypted_text'] == encrypted_text:
                salt = bytes.fromhex(value['salt'])
                hashed_key, _ = hash_passkey(passkey, salt)
                
                if value['passkey'] == hashed_key.decode():
                    st.session_state.failed_attempts = 0
                    st.session_state.last_attempt_time = None
                    return cipher.decrypt(encrypted_text.encode()).decode()
        
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = datetime.now()
        return None
    except Exception as e:
        st.error(f"Error during decryption: {str(e)}")
        return None

# Streamlit UI
st.set_page_config(page_title="Secure Data Encryption System", page_icon="🔒")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.title("🔒 Secure Data Encryption System")
    st.write("""
    Welcome to the Secure Data Encryption System! This application allows you to:
    - Store sensitive data securely using encryption
    - Retrieve your data using a unique passkey
    - Protect your data with multiple security layers
    """)
    
    if st.session_state.failed_attempts > 0:
        st.warning(f"⚠️ Failed attempts: {st.session_state.failed_attempts}")

# Store Data Page
elif choice == "Store Data":
    st.title("📂 Store Data Securely")
    
    user_data = st.text_area("Enter Data to Encrypt:")
    passkey = st.text_input("Create a Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    
    if st.button("Encrypt & Save"):
        if not user_data or not passkey or not confirm_passkey:
            st.error("⚠️ All fields are required!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys do not match!")
        else:
            encrypted_text, hashed_key, salt = encrypt_data(user_data, passkey)
            if encrypted_text and hashed_key and salt:
                stored_data[encrypted_text] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_key,
                    "salt": salt
                }
                save_data(stored_data)
                st.success("✅ Data stored securely!")
                st.info("🔑 Please save your encrypted data and passkey securely!")
                st.text_area("Your Encrypted Data:", encrypted_text, height=100)

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.title("🔍 Retrieve Your Data")
    
    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.warning("🔒 Too many failed attempts! Please login to continue.")
        st.stop()
    
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Decrypt"):
        if not encrypted_text or not passkey:
            st.error("⚠️ Both fields are required!")
        else:
            decrypted_text = decrypt_data(encrypted_text, passkey)
            
            if decrypted_text:
                st.success("✅ Data decrypted successfully!")
                st.text_area("Decrypted Data:", decrypted_text, height=200)
            else:
                attempts_remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {attempts_remaining}")
                
                if st.session_state.failed_attempts >= MAX_ATTEMPTS:
                    st.warning("🔒 Account locked. Please login to continue.")
                    st.experimental_rerun()

# Login Page
elif choice == "Login":
    st.title("🔑 Reauthorization Required")
    
    if st.session_state.is_authenticated:
        st.success("✅ You are already authenticated!")
        if st.button("Continue to Retrieve Data"):
            st.experimental_rerun()
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")
        
        if st.button("Login"):
            if login_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.session_state.last_attempt_time = None
                st.session_state.is_authenticated = True
                st.success("✅ Reauthorized successfully!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password! Please try again.") 