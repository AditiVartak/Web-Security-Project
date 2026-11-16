"""Create or change the dashboard admin account.

Run in your own terminal:   python set_admin_password.py
The password is typed hidden and stored only as a salted hash in admin_credentials.json.
Changing the password logs out every existing dashboard session.
"""
import getpass
import sys

from src.hybrid_waf.utils.admin_auth import (MIN_PASSWORD_LENGTH, credentials_path,
                                             load_credentials, write_credentials)


def main():
    existing = load_credentials()
    default_user = existing["username"] if existing else "admin"
    username = input(f"Admin username [{default_user}]: ").strip() or default_user
    password = getpass.getpass(f"New password (min {MIN_PASSWORD_LENGTH} chars): ")
    if password != getpass.getpass("Repeat password: "):
        sys.exit("Passwords do not match. Nothing was changed.")
    try:
        write_credentials(username, password)
    except ValueError as e:
        sys.exit(f"Error: {e}")
    print(f"Saved to {credentials_path()}. Start the app and open /login.")


if __name__ == "__main__":
    main()
