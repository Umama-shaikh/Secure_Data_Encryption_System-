import streamlit as st 
import hashlib 
import json 
import os
import time 
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value" 
LOCKOUT_DURATION = 60


# login details 
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "login_attempts" not in st.session_state:
    st.session_state.failed_login_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# if data is load
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as file:
            return json.load(file)
    return{}

def save_data(data):
    with open(DATA_FILE, "w") as file:
        json.dump(data, file)


def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# cryptography.fernet used 
def encrypt_data(text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()

# navigation bar

st.title("🔐 Secure Data Storage")
menu = ["Home","Register","Login","Store Data","Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)


if choice == "Home":
    st.subheader("Welcome to My Data Encryption System 🔐")
    st.markdown("This is a simple data encryption system that allows you to securely store and retrieve sensitive information.")


# user registration 
elif choice == "Register":
    st.subheader("✏ Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("Username already exists. Please choose a different username.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("User registered successfully!")
        else:
            st.error("Please enter both username and password.")
    
    
elif choice == "Login":
        st.subheader("🔑 User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"Too many failed attempts. Please wait {remaining} seconds before trying again.")
            st.stop()

        username = st.text_input("Username")
        password = st.text_input("Password", type="password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_login_attempts = 0
                st.success(f"Welcome, {username}!") 
            else:
                st.session_state.failed_login_attempts += 1
                remaining = 3 - st.session_state.failed_login_attempts
                st.error(f"Invalid Credentials. You have {remaining} attempts left.")

                if st.session_state.failed_login_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Too many failed attempts. Please wait 60 seconds before trying again.")
                    st.stop()

# data store section

elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("Please log in to store data.")
    else:
        st.subheader("💾 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption key (passphrase)", type="password")


        if st.button("Encrypt and Store"):
            if data and passkey:
                encrypted = encrypt_data(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("Data encrypted and stored successfully!")
            else:
                st.error("All fields are required to fill.")

# data retieve data section

elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("Please log in first.")
    else:
        st.subheader("🔍 Retrieve Data")
        user_data = stored_data(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found for the user.")
        else:
            st.write("Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")

            encrypted_input = st.text_input("Enter encrypted text")
            passkey = st.text_input("Enter passkey to decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted Data: {result}")
                else:
                    st.error("Decryption failed. Please check the encrypted text and passkey.")




