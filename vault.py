import json
from cryptography.fernet import Fernet
import os

# Load or generate encryption key
if not os.path.exists("key.key"):
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
else:
    with open("key.key", "rb") as key_file:
        key = key_file.read()

fernet = Fernet(key)

# Load existing vault
if os.path.exists("vault.json"):
    with open("vault.json", "r") as file:
        vault = json.load(file)
else:
    vault = {}

# Functions
def add_credential():
    account = input("Enter account name: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    encrypted_password = fernet.encrypt(password.encode()).decode()
    vault[account] = {"username": username, "password": encrypted_password}
    save_vault()
    print(f"Credential for '{account}' added successfully!")

def retrieve_credential():
    account = input("Enter account name to retrieve: ")
    if account in vault:
        encrypted_password = vault[account]["password"]
        password = fernet.decrypt(encrypted_password.encode()).decode()
        username = vault[account]["username"]
        print(f"Account: {account}\nUsername: {username}\nPassword: {password}")
    else:
        print(f"No credentials found for '{account}'")

def list_accounts():
    if vault:
        print("Stored accounts:")
        for account in vault:
            print(f"- {account}")
    else:
        print("Vault is empty.")

def update_credential():
    account = input("Enter account name to update: ")
    if account in vault:
        new_password = input("Enter new password: ")
        encrypted_password = fernet.encrypt(new_password.encode()).decode()
        vault[account]["password"] = encrypted_password
        save_vault()
        print(f"Password for '{account}' updated successfully!")
    else:
        print(f"No credentials found for '{account}'")

def delete_credential():
    account = input("Enter account name to delete: ")
    if account in vault:
        del vault[account]
        save_vault()
        print(f"Credential for '{account}' deleted successfully!")
    else:
        print(f"No credentials found for '{account}'")

def save_vault():
    with open("vault.json", "w") as file:
        json.dump(vault, file, indent=4)

# Menu
while True:
    print("\n=== Personal Vault Menu ===")
    print("1. Add Credential")
    print("2. Retrieve Credential")
    print("3. List All Accounts")
    print("4. Update Credential")
    print("5. Delete Credential")
    print("6. Exit")
    choice = input("Enter your choice (1-6): ")

    if choice == "1":
        add_credential()
    elif choice == "2":
        retrieve_credential()
    elif choice == "3":
        list_accounts()
    elif choice == "4":
        update_credential()
    elif choice == "5":
        delete_credential()
    elif choice == "6":
        print("Exiting Personal Vault. Stay secure!")
        break
    else:
        print("Invalid choice. Please enter a number between 1 and 6.")
