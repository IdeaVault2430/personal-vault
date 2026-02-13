import json
import os
import base64
import time
import sys
import platform
import threading
import subprocess
from typing import Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# === Config ===
VAULT_FILE = "vault.json"
SALT_FILE = "salt.key"
VERIFIER_FILE = "verifier.bin"
LEGACY_KEY_FILE = "key.key"
PBKDF2_ITERATIONS = 390_000

IDLE_TIMEOUT = 60         # seconds
REMINDER_TIME = 50        # seconds (start countdown at IDLE_TIMEOUT - REMINDER_TIME)
CLIPBOARD_CLEAR_SECONDS = 20

# === State ===
fernet: Optional[Fernet] = None
vault: Dict[str, Dict[str, str]] = {}
last_activity: float = time.time()
reminder_shown: bool = False
PASSWORD_VISIBLE: bool = False  # default hidden


# === Low-level helpers ===
def _derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    key = kdf.derive(master_password.encode("utf-8"))
    return base64.urlsafe_b64encode(key)


def _write_bytes(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _read_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# === Clipboard helper with auto-install and auto-clear ===
def ensure_pyperclip() -> Optional[object]:
    try:
        import pyperclip
        return pyperclip
    except Exception:
        # attempt auto-install
        try:
            print("pyperclip not installed — attempting to install via pip...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", "pyperclip"])
            import pyperclip
            return pyperclip
        except Exception as e:
            print("Failed to install pyperclip:", e)
            return None


def copy_to_clipboard_and_clear(text: str, timeout: int = CLIPBOARD_CLEAR_SECONDS):
    py = ensure_pyperclip()
    if not py:
        print("Clipboard copy not available (pyperclip missing).")
        return
    py.copy(text)
    print(f"Password copied to clipboard — it will be cleared in {timeout} seconds.")
    def clear_clipboard():
        try:
            # only clear if clipboard still contains the same text
            if py.paste() == text:
                py.copy("")
                print("Clipboard cleared.")
        except Exception:
            pass
    t = threading.Timer(timeout, clear_clipboard)
    t.daemon = True
    t.start()


# === OS-level small-getch ===
def get_single_char() -> str:
    """Return a single character from stdin without echo. Cross-platform."""
    if platform.system() == "Windows":
        import msvcrt
        ch = msvcrt.getwch()
        return ch
    else:
        # Unix-like
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def drain_input_buffer():
    """Flush any leftover keystrokes so next prompt is clean."""
    if platform.system() == "Windows":
        import msvcrt
        while msvcrt.kbhit():
            msvcrt.getwch()
    else:
        try:
            import termios
            termios.tcflush(sys.stdin, termios.TCIFLUSH)
        except Exception:
            pass


# === Password strength ===
def password_strength_label(pw: str) -> str:
    score = 0
    if len(pw) >= 8:
        score += 1
    if any(c.islower() for c in pw) and any(c.isupper() for c in pw):
        score += 1
    if any(c.isdigit() for c in pw):
        score += 1
    if any(not c.isalnum() for c in pw):
        score += 1
    if score <= 1:
        return "Weak"
    if score == 2:
        return "Medium"
    return "Strong"


# === Load/save vault ===
def load_vault():
    global vault
    if os.path.exists(VAULT_FILE):
        try:
            with open(VAULT_FILE, "r", encoding="utf-8") as f:
                vault = json.load(f)
        except Exception:
            vault = {}
    else:
        vault = {}


def save_vault():
    with open(VAULT_FILE, "w", encoding="utf-8") as f:
        json.dump(vault, f, indent=4, ensure_ascii=False)


# === Master password setup/unlock ===
def ensure_master_setup():
    if os.path.exists(SALT_FILE) and os.path.exists(VERIFIER_FILE):
        return
    print("\n— First-time setup —")
    while True:
        pw1 = prompt_password_with_toggle("Create a master password")
        pw2 = prompt_password_with_toggle("Confirm master password")
        if not pw1:
            print("Master password cannot be empty.")
            continue
        if pw1 != pw2:
            print("Passwords don't match. Try again.\n")
            continue
        break
    salt = os.urandom(16)
    key = _derive_key(pw1, salt)
    f = Fernet(key)
    token = f.encrypt(b"vault-unlock-ok")
    _write_bytes(SALT_FILE, salt)
    _write_bytes(VERIFIER_FILE, token)
    print("Master password set. Keep it safe — losing it means losing access to the vault!\n")


def unlock_fernet(max_attempts: int = 3) -> Fernet:
    salt = _read_bytes(SALT_FILE)
    verifier = _read_bytes(VERIFIER_FILE)
    for attempt in range(1, max_attempts + 1):
        pw = prompt_password_with_toggle("Master password")
        key = _derive_key(pw, salt)
        f = Fernet(key)
        try:
            data = f.decrypt(verifier)
            if data == b"vault-unlock-ok":
                print("Unlocked ✅\n")
                return f
        except InvalidToken:
            pass
        print(f"Invalid password (attempt {attempt}/{max_attempts}).")
    raise SystemExit("Too many failed attempts. Exiting.")


# === Input helpers: timed menu + password prompts ===
def key_pressed_nonblocking() -> Optional[str]:
    """Return a pressed key (single char) if available, else None (non-blocking)."""
    if platform.system() == "Windows":
        import msvcrt
        if msvcrt.kbhit():
            return msvcrt.getwch()
        return None
    else:
        import select
        dr, _, _ = select.select([sys.stdin], [], [], 0)
        if dr:
            return sys.stdin.read(1)
        return None


def prompt_password_with_toggle(prompt_label: str) -> str:
    """
    Prompt for password with:
     - default: hidden (getpass)
     - type 'S' as the whole input to switch to visible mode for the session
     - while typing, press Ctrl+T to toggle visible/hidden live (works cross-platform)
    Returns the entered password (string).
    """
    global PASSWORD_VISIBLE
    # If visibility already set to visible, use visible input
    if PASSWORD_VISIBLE:
        return input(f"{prompt_label} (visible): ").strip()

    # Hidden mode: use getpass but allow 'S' to switch or Ctrl+T to toggle live
    try:
        import getpass
    except Exception:
        # fallback
        return input(f"{prompt_label} (visible): ").strip()

    # We'll implement hidden input with live Ctrl+T detection.
    sys.stdout.write(f"{prompt_label} (hidden, type S to show, or Ctrl+T to toggle): ")
    sys.stdout.flush()
    buf_chars = []
    while True:
        ch = get_single_char()
        # Detect Enter
        if ch in ("\r", "\n"):
            sys.stdout.write("\n")
            pw = "".join(buf_chars)
            # If user typed single 'S' to mean show mode, switch
            if pw.strip().upper() == "S":
                PASSWORD_VISIBLE = True
                return input(f"{prompt_label} (visible): ").strip()
            return pw
        # Detect backspace/delete
        if ch in ("\x08", "\x7f"):
            if buf_chars:
                buf_chars.pop()
                # move cursor back, overwrite, move back
                sys.stdout.write("\b \b")
                sys.stdout.flush()
            continue
        # Detect Ctrl+T toggle (ASCII 20)
        if ch == "\x14":
            # toggle visible live — if currently hidden, switch to visible and let user continue typing
            PASSWORD_VISIBLE = not PASSWORD_VISIBLE
            if PASSWORD_VISIBLE:
                # show current buffer visibly and continue using input()
                current = "".join(buf_chars)
                print("\n[Visibility toggled ON — continuing visible input]")
                # use Python input to capture remaining characters (user completes and presses Enter)
                rest = input(f"{prompt_label} (visible, resume): {current}")
                return rest.strip()
            else:
                print("\n[Visibility toggled OFF — continuing hidden input]")
                # continue hidden input; buf_chars remains
                sys.stdout.write(f"{prompt_label} (hidden): ")
                sys.stdout.flush()
                continue
        # Regular character -> append and echo '*' for hidden input
        buf_chars.append(ch)
        sys.stdout.write("*")
        sys.stdout.flush()


# === Idle lock / countdown / beep ===
def beep():
    if platform.system() == "Windows":
        try:
            import winsound
            winsound.Beep(1000, 180)
        except Exception:
            sys.stdout.write("\a")
            sys.stdout.flush()
    else:
        sys.stdout.write("\a")
        sys.stdout.flush()


def show_countdown(seconds: int):
    global last_activity, reminder_shown
    print("\n⏳ Vault will auto-lock soon. Press ANY key to cancel countdown.")
    for i in range(seconds, 0, -1):
        sys.stdout.write(f"\rAuto-lock in {i} seconds...    ")
        sys.stdout.flush()
        beep()
        # non-blocking check for any key — if any key pressed, cancel countdown
        k = key_pressed_nonblocking()
        if k:
            print("\n✅ Countdown cancelled. Activity reset.")
            reset_activity()
            drain_input_buffer()
            return
        time.sleep(1)
    print("\n")


def check_idle_timeout():
    global fernet, last_activity, reminder_shown
    idle_time = time.time() - last_activity
    if idle_time > IDLE_TIMEOUT:
        print("\n⚠️  Session locked due to inactivity. Please re-enter your master password.\n")
        fernet_local = unlock_fernet()
        # replace global fernet with returned fernet
        globals()['fernet'] = fernet_local
        reset_activity()
        drain_input_buffer()
        reminder_shown = False
    elif idle_time > REMINDER_TIME and not reminder_shown:
        show_countdown(IDLE_TIMEOUT - REMINDER_TIME)
        reminder_shown = True


def reset_activity():
    global last_activity, reminder_shown
    last_activity = time.time()
    reminder_shown = False


# === Timed menu input (non-blocking loop building input) ===
def timed_input(prompt: str) -> str:
    sys.stdout.write(prompt)
    sys.stdout.flush()
    buf = []
    while True:
        check_idle_timeout()
        k = key_pressed_nonblocking()
        if k:
            # Enter
            if k in ("\r", "\n"):
                sys.stdout.write("\n")
                reset_activity()
                return "".join(buf).strip()
            # Backspace
            if k in ("\x08", "\x7f"):
                if buf:
                    buf.pop()
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
                continue
            # Regular char
            buf.append(k)
            sys.stdout.write(k)
            sys.stdout.flush()
        time.sleep(0.05)


# === CRUD operations ===
def add_credential():
    check_idle_timeout()
    account = timed_input("Enter account name: ")
    if not account:
        print("Account name cannot be empty.")
        return
    username = timed_input("Enter username: ")
    password = prompt_password_with_toggle("Enter password")
    enc_pw = fernet.encrypt(password.encode("utf-8")).decode("utf-8")
    vault[account] = {"username": username, "password": enc_pw}
    save_vault()
    reset_activity()
    print(f"Credential for '{account}' added successfully!")


def retrieve_credential():
    check_idle_timeout()
    account = timed_input("Enter account name to retrieve: ")
    if account in vault:
        enc_pw = vault[account]["password"]
        try:
            pw = fernet.decrypt(enc_pw.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            print("❌ Unable to decrypt this entry with the current master key.")
            return
        username = vault[account]["username"]
        reset_activity()
        print(f"\nAccount : {account}\nUsername: {username}\nPassword: {pw}\n")
        # Ask to copy to clipboard
        ans = timed_input("Copy password to clipboard? (y/n): ").lower()
        if ans == "y":
            copy_to_clipboard_and_clear(pw, CLIPBOARD_CLEAR_SECONDS)
    else:
        print(f"No credentials found for '{account}'.")


def list_accounts():
    check_idle_timeout()
    if vault:
        print("Stored accounts:")
        for name in sorted(vault.keys(), key=str.lower):
            print(f"- {name}")
    else:
        print("Vault is empty.")
    reset_activity()


def update_credential():
    check_idle_timeout()
    account = timed_input("Enter account name to update: ")
    if account in vault:
        while True:
            new_pw = prompt_password_with_toggle("Enter new password")
            confirm = prompt_password_with_toggle("Confirm new password")
            if new_pw != confirm:
                print("Passwords don't match — try again.")
                continue
            break
        enc_pw = fernet.encrypt(new_pw.encode("utf-8")).decode("utf-8")
        vault[account]["password"] = enc_pw
        save_vault()
        reset_activity()
        print(f"Password for '{account}' updated successfully!")
    else:
        print(f"No credentials found for '{account}'.")


def delete_credential():
    check_idle_timeout()
    account = timed_input("Enter account name to delete: ")
    if account in vault:
        confirm = timed_input(f"Type the account name ('{account}') to confirm deletion: ")
        if confirm == account:
            del vault[account]
            save_vault()
            reset_activity()
            print(f"Credential for '{account}' deleted successfully!")
        else:
            print("Deletion cancelled.")
    else:
        print(f"No credentials found for '{account}'.")


def migrate_from_legacy():
    check_idle_timeout()
    if not os.path.exists(LEGACY_KEY_FILE):
        print("No legacy key.key found. Nothing to migrate.")
        return
    try:
        legacy_key = _read_bytes(LEGACY_KEY_FILE)
        legacy_f = Fernet(legacy_key)
    except Exception as e:
        print("Failed to load legacy key:", e)
        return
    migrated, skipped = 0, 0
    for account, rec in list(vault.items()):
        enc_pw = rec.get("password", "")
        if not enc_pw:
            continue
        try:
            plain = legacy_f.decrypt(enc_pw.encode("utf-8")).decode("utf-8")
            rec["password"] = fernet.encrypt(plain.encode("utf-8")).decode("utf-8")
            migrated += 1
        except InvalidToken:
            skipped += 1
            continue
    save_vault()
    try:
        os.replace(LEGACY_KEY_FILE, LEGACY_KEY_FILE + ".bak")
    except Exception:
        pass
    reset_activity()
    print(f"Migration complete. Migrated: {migrated}, skipped: {skipped}.")


# === Entry point ===
def main():
    ensure_master_setup()
    global fernet
    global PASSWORD_VISIBLE
    fernet = unlock_fernet()
    reset_activity()
    load_vault()
    drain_input_buffer()

    while True:
        print("\n=== Personal Vault (Secure) ===")
        print("1. Add Credential")
        print("2. Retrieve Credential")
        print("3. List All Accounts")
        print("4. Update Credential")
        print("5. Delete Credential")
        print("6. Migrate from legacy (key.key)")
        print("7. Exit")
        print(f"8. Toggle Password Visibility (current: {'Visible' if PASSWORD_VISIBLE else 'Hidden'})")

        choice = timed_input("Enter your choice (1-8): ").strip()
        if not choice:
            continue
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
            migrate_from_legacy()
        elif choice == "7":
            print("Exiting. Stay secure! ✨")
            break
        elif choice == "8":
            PASSWORD_VISIBLE = not PASSWORD_VISIBLE
            print(f"Password visibility is now: {'Visible' if PASSWORD_VISIBLE else 'Hidden'}")
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")


if __name__ == "__main__":
    main()