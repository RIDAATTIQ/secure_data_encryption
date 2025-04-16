# 🔒 Secure Data Encryption System using Streamlit

This is a simple Streamlit-based secure data storage and retrieval system.

## 💡 Features

- Store secret data using a secure passkey.
- Retrieve your data using the correct passkey only.
- 3 wrong attempts = forced re-login.
- In-memory storage (no external database).
- Real-time UI using Streamlit.

## 🛡️ Tech Used

- Python
- Streamlit
- Cryptography (Fernet Encryption)
- Hashlib (SHA-256)

## 🚀 How to Run

```bash
pip install -r requirements.txt
streamlit run app.py
