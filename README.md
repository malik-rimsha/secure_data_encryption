# 🔒 Secure Data Encryption System

A Streamlit-based application for secure data storage and retrieval using encryption.

## Features

- 🔐 Secure data encryption using Fernet (symmetric encryption)
- 🔑 Passkey-based authentication
- ⏱️ Time-based lockout after multiple failed attempts
- 💾 Data persistence using JSON storage
- 🛡️ Enhanced security with PBKDF2 key derivation

## Installation

1. Clone this repository
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```bash
   streamlit run app.py
   ```

2. Navigate through the application using the sidebar:
   - **Home**: Overview of the system
   - **Store Data**: Encrypt and store new data
   - **Retrieve Data**: Decrypt and view stored data
   - **Login**: Reauthorization page for locked accounts

## Security Notes

- The master password is currently set to "admin123" for demonstration purposes
- In a production environment, you should:
  - Store the encryption key securely
  - Implement proper user authentication
  - Use environment variables for sensitive data
  - Consider using a proper database instead of JSON files

## Requirements

- Python 3.7+
- Streamlit
- Cryptography
- Python-dotenv
 
