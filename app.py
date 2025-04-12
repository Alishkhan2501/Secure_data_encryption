# ====  Importing Required Libraries ====
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode, b64encode
from hashlib import pbkdf2_hmac

# ==== Constants ====
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

# ==== Set Background Safely ====
def set_background(image_path):
    try:
        # Normalize path and check file exists
        image_path = os.path.join(os.path.dirname(__file__), image_path)
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"File not found: {image_path}")

        with open(image_path, "rb") as image_file:
            encoded_string = b64encode(image_file.read()).decode()
        st.markdown(f"""
            <style>
            .stApp {{
                background-image: url('data:image/jpeg;base64,{encoded_string}');
                background-size: cover;
                background-position: center;
                background-repeat: no-repeat;
                min-height: 100vh;
            }}
            </style>
        """, unsafe_allow_html=True)

        st.markdown("""
            <style>
            h1, h2, h3, h4, h5, h6, .stMarkdown, .stText, .stSubheader, .stTitle {
                color: white !important;
            }
            label, .stTextInput label, .stTextArea label {
                color: white !important;
            }
            .stTextInput div input, .stTextArea textarea {
                color: black !important;
                background-color: rgba(0, 0, 0, 0.6) !important;
            }
            section[data-testid="stSidebar"] {
                background-color: #09143C !important;
                color: white !important;
            }
            .stButton button {
                color: black !important;
            }
            </style>
        """, unsafe_allow_html=True)
    except Exception as e:
        st.warning(f"⚠️ Background not loaded: {str(e)}")

# Set Background
set_background("image/securr.jpg")

# ==== Session State Setup ====
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# ==== Load and Save JSON ====
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# ==== Hashing and Encryption ====
def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()

def encrypt_text(text, passkey):
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypted_text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# ==== Load User Data ====
stored_data = load_data()

# ==== UI ====
st.title("🔐 Secure Data Encryption System")
menu = ["Home", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("🔎 Navigate", menu)

# ==== Home Page ====
if choice == "Home":
    st.subheader("🏠 Welcome!")
    st.markdown("""
        🔒 **Secure Data Encryption System** empowers you to:
        - 🛡️ **Store sensitive data securely**
        - 🔑 **Decrypt with passkey**
        - 🚫 **Lockout after failed attempts**
        - 💾 **Stored in local JSON**
        - ⚡ **Simple, Safe, Secure**
    """)

# ==== Login ====
elif choice == "Login":
    st.subheader("🔐 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🔒 Locked. Try again in {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome, {username}!")
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.error(f"❌ Invalid credentials. Attempts left: {remaining}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🔒 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# ==== Store Data ====
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("📥 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ Both fields are required.")

# ==== Retrieve Data ====
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔑 Please login first.")
    else:
        st.subheader("🔓 Retrieve & Decrypt Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No stored data found.")
        else:
            st.write("📄 Stored Encrypted Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_area("Paste Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts. Re-login required.")
                    st.session_state.authenticated_user = None
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.rerun()

                if encrypted_input and passkey:
                    result = decrypt_text(encrypted_input, passkey)
                    if result:
                        st.success("✅ Decryption Successful!")
                        st.code(result, language="text")
                        st.session_state.failed_attempts = 0
                    else:
                        st.session_state.failed_attempts += 1
                        remaining = 3 - st.session_state.failed_attempts
                        st.error(f"❌ Incorrect passkey. Attempts left: {remaining}")
                        if remaining <= 0:
                            st.warning("🔒 Too many failed attempts. Logging out...")
                            st.session_state.authenticated_user = None
                            st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                            st.rerun()
                else:
                    st.error("⚠️ Both fields are required.")

