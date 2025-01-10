import os
import json
import sqlite3
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import win32crypt

# Paths to the required files
local_state_file = os.path.join(os.getcwd(), "Local State.txt")
login_data_file = os.path.join(os.getcwd(), "Login Data.txt")

# Ensure the required files exist
if not os.path.exists(local_state_file) or not os.path.exists(login_data_file):
    print("Error: Required files 'Local State' or 'Login Data' not found in the current directory.")
    exit()

# Extract the master key from the Local State file
with open(local_state_file, "r", encoding="utf-8") as f:
    local_state = json.load(f)
encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
encrypted_key = base64.b64decode(encrypted_key_b64)[5:]  # Remove 'DPAPI' prefix
master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

# Connect to the SQLite database
connection = sqlite3.connect(login_data_file)
cursor = connection.cursor()

# Query saved credentials
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
results = cursor.fetchall()

# Decrypt and print the credentials
print("Decrypted Chrome Passwords:")
print("=" * 50)

for origin_url, username, encrypted_password in results:
    try:
        # Try decrypting the password
        if encrypted_password[:3] == b'v10':  # AES-GCM encrypted password
            nonce, ciphertext = encrypted_password[3:15], encrypted_password[15:]
            aesgcm = AESGCM(master_key)
            decrypted_password = aesgcm.decrypt(nonce, ciphertext, None).decode()
        else:  # DPAPI-encrypted password
            decrypted_password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
        
        print(f"URL: {origin_url}")
        print(f"Username: {username}")
        print(f"Password: {decrypted_password}")
        print("-" * 50)
    except Exception as e:
        print(f"Failed to decrypt entry for URL: {origin_url}, Error: {str(e)}")

# Clean up
cursor.close()
connection.close()