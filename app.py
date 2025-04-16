import hashlib
import streamlit as st
from cryptography.fernet import Fernet

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed_passkey"}}
failed_attempts = 0
MAX_ATTEMPTS = 3

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt data
def encrypt_data(text, passkey):
    hashed_passkey = hash_passkey(passkey)
    encrypted_text = cipher.encrypt(text.encode()).decode()
    return encrypted_text, hashed_passkey

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts
    hashed_passkey = hash_passkey(passkey)

    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Sidebar Menu
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Home Page
if choice == "Home":
    st.write("Welcome to the Secure Data Encryption System!")
    st.write("You can store encrypted data and retrieve it securely here.")
    
    if failed_attempts >= MAX_ATTEMPTS:
        st.warning("You have failed 3 attempts. Please log in again.")
        if st.button("Go to Login Page"):
            st.session_state['login'] = True
            st.experimental_rerun()

# Store Data Page
elif choice == "Store Data":
    st.subheader("Store Your Data Securely")

    # User inputs data and passkey for encryption
    text_to_store = st.text_area("Enter Data to Store:")
    passkey = st.text_input("Enter Passkey (for encryption):", type="password")
    
    # Add a button to store the data
    if st.button("Store Data"):
        if text_to_store and passkey:
            encrypted_text, hashed_passkey = encrypt_data(text_to_store, passkey)
            # Store the encrypted data and passkey in the dictionary
            stored_data[text_to_store] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
            st.success("Data stored securely!")
            
            # Show stored data as a confirmation below the button
            st.write("Stored Data: ")
            st.write(f"Encrypted Text: {encrypted_text}")
            st.write(f"Passkey (hashed): {hashed_passkey[:20]}...")  # Display only part of the hashed passkey for security reasons
            
            # Option to see the stored data below the button
            if st.checkbox("Show all stored data"):
                st.write(stored_data)
        else:
            st.error("Please enter both data and passkey.")

# Retrieve Data Page
elif choice == "Retrieve Data":
    st.subheader("Retrieve Your Data")

    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    
    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {MAX_ATTEMPTS - failed_attempts}")
                if failed_attempts >= MAX_ATTEMPTS:
                    st.warning("You have failed 3 attempts. Please log in again.")
                    if st.button("Go to Login Page"):
                        st.session_state['login'] = True
                        st.experimental_rerun()
        else:
            st.error("Please enter both encrypted data and passkey.")

# Login Page
elif choice == "Login":
    st.write("Please reauthorize to continue.")
    # You can add more login-related functionality here if required.
