import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet, InvalidToken

USER_DB_FILE = "users.json"
DATA_FILE = "stored_data.json"

# --- Load or Initialize Data ---
def load_json(file, default):
    if os.path.exists(file):
        with open(file, "r") as f:
            return json.load(f)
    return default

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# --- Load Persistent Data ---
users = load_json(USER_DB_FILE, {})
stored_data = load_json(DATA_FILE, {})

# --- Session State Initialization ---
for key in ["logged_in", "username", "failed_attempts", "show_login", "decryption_history"]:
    if key not in st.session_state:
        st.session_state[key] = False if key == "logged_in" else [] if key == "decryption_history" else None

# --- Utility Functions ---
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_user_key(username):
    return hashlib.sha256(username.encode()).digest()

def get_cipher(username):
    return Fernet(Fernet.generate_key())

def register_user(username, password):
    if username in users:
        return False
    key = Fernet.generate_key().decode()
    users[username] = {
        "password": hash_password(password),
        "key": key
    }
    save_json(USER_DB_FILE, users)
    return True

def authenticate_user(username, password):
    if username in users and users[username]["password"] == hash_password(password):
        return True
    return False

def encrypt_data(text, username):
    key = users[username]["key"].encode()
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, username):
    if users[username]["password"] != hash_password(passkey):
        st.session_state.failed_attempts += 1
        st.error("❌ Incorrect password!")
        return None
    try:
        key = users[username]["key"].encode()
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode()
    except InvalidToken as e:
        st.session_state.failed_attempts += 1
        st.error(f"❌ Decryption failed: {e}")
        return None
    except Exception as e:
        st.session_state.failed_attempts += 1
        st.error(f"❌ Decryption error: {e}")
        return None

# --- Login Page ---
def login_page():
    st.subheader("🔐 Login to Secure Data App")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.session_state.show_login = False
            st.success("✅ Logged in successfully!")
            st.rerun()
        else:
            st.error("❌ Invalid credentials!")

def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.session_state.decryption_history = []
    st.session_state.failed_attempts = 0
    st.success("✅ Logged out!")
    st.rerun()

# --- Register Page ---
def register_page():
    st.subheader("📝 Register")
    new_user = st.text_input("New Username")
    new_pass = st.text_input("New Password", type="password")
    if st.button("Register"):
        if register_user(new_user, new_pass):
            st.success("✅ Registration successful! You can now login.")
        else:
            st.error("❌ Username already exists.")

# --- App Layout ---
st.set_page_config("Secure Data Encryption", "🔐")
st.title("🔐 Secure Data Encryption System")

menu = ["Login", "Register", "Encrypt", "Decrypt", "History", "Logout"]
choice = st.sidebar.selectbox("📂 Menu", menu)

if choice == "Login":
    if not st.session_state.logged_in:
        login_page()
    else:
        st.info(f"✅ Already logged in as {st.session_state.username}")

elif choice == "Register":
    register_page()

elif choice == "Encrypt":
    if st.session_state.logged_in:
        st.subheader("🔒 Encrypt Data")
        data = st.text_area("Enter data to encrypt")
        if st.button("Encrypt & Store"):
            if data:
                encrypted = encrypt_data(data, st.session_state.username)
                stored_data[encrypted] = st.session_state.username
                save_json(DATA_FILE, stored_data)
                st.success("✅ Data encrypted and stored!")
                st.code(encrypted)
            else:
                st.error("⚠️ Please enter some text.")
    else:
        st.warning("🔐 Please login to encrypt data.")

elif choice == "Decrypt":
    if st.session_state.failed_attempts >= 3:
        st.warning("🔐 Too many failed attempts. Please login again.")
        st.session_state.logged_in = False
        st.rerun()

    if st.session_state.logged_in:
        st.subheader("🔓 Decrypt Data")
        encrypted_input = st.text_area("Paste encrypted text")
        passkey = st.text_input("Enter your password", type="password")
        if st.button("Decrypt"):
            result = decrypt_data(encrypted_input, passkey, st.session_state.username)
            if result:
                st.success("✅ Decrypted successfully:")
                st.code(result)
                st.session_state.decryption_history.append(result)
                st.session_state.failed_attempts = 0
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Decryption failed. Attempts left: {attempts_left}")
    else:
        st.warning("🔐 Please login to decrypt data.")

elif choice == "History":
    if st.session_state.logged_in:
        st.subheader("📜 Decryption History")
        if st.session_state.decryption_history:
            for i, item in enumerate(st.session_state.decryption_history, 1):
                st.write(f"{i}. {item}")
        else:
            st.info("📝 No history yet.")
    else:
        st.warning("🔐 Please login to view history.")

elif choice == "Logout":
    if st.session_state.logged_in:
        logout()
    else:
        st.info("🚪 You are not logged in.")