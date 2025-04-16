import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Session State Initialization
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # {encrypted_text: {encrypted_text, passkey}}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'is_logged_in' not in st.session_state:
    st.session_state.is_logged_in = True

# Generate a global encryption key
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Hashing function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt text using Fernet
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decrypt text using Fernet with passkey verification
def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    data_entry = st.session_state.stored_data.get(encrypted_text)

    if data_entry and data_entry["passkey"] == hashed:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

# Main App UI
st.set_page_config(page_title="Secure Data Encryption System", layout="centered")
st.title("🔐 Secure Data Encryption System")

# Sidebar Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.radio("Navigation", menu)

# Home Page
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Use this app to **securely store and retrieve text** using encryption and a secret passkey.")

# Store Data
elif choice == "Store Data":
    st.subheader("📦 Store Encrypted Data")
    user_data = st.text_area("Enter your data:")
    passkey = st.text_input("Set a passkey:", type="password")

    if st.button("Encrypt & Store"):
        if user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            st.session_state.stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted, language="text")
        else:
            st.error("⚠️ Please enter both data and a passkey.")

# Retrieve Data
elif choice == "Retrieve Data":
    if not st.session_state.is_logged_in:
        st.warning("🔒 You are locked out. Please reauthorize from the Login page.")
    else:
        st.subheader("🔎 Retrieve Encrypted Data")
        encrypted_text = st.text_area("Paste your encrypted data:")
        passkey = st.text_input("Enter your passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                result = decrypt_data(encrypted_text, passkey)
                if result:
                    st.success("✅ Decryption Successful:")
                    st.code(result, language="text")
                else:
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                    if st.session_state.failed_attempts >= 3:
                        st.session_state.is_logged_in = False
                        st.warning("🚫 Too many failed attempts! Please log in again.")
                        st.experimental_rerun()
            else:
                st.error("⚠️ Both fields are required!")

# Login Page
elif choice == "Login":
    st.subheader("🔑 Reauthorization")
    login_pass = st.text_input("Enter master password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.is_logged_in = True
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized! You may now access decryption again.")
        else:
            st.error("❌ Incorrect password.")
