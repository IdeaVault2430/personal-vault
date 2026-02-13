import json
from cryptography.fernet import Fernet
import os

# Load encryption key
with open("key.key", "rb") as key_file:
    key = key_file.read()

fernet = Fernet(key)

# Load existing vault
if os.path.exists("vault.json"):
    with open("vault.json", "r") as file:
        vault = json.load(file)
else:
    vault = {}

def retrieve_credential(account):
    if account in vault:
        encrypted_password = vault[account]["password"]
        password = fernet.decrypt(encrypted_password.encode()).decode()
        username = vault[account]["username"]
        print(f"Account: {account}")
        print(f"Username: {username}")
        print(f"Password: {password}")
    else:
        print(f"No credentials found for '{account}'")

# Example usage
account_name = input("Enter account name to retrieve: ")
retrieve_credential(account_name)
