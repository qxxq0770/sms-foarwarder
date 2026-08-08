import argparse
import getpass

from app.config import Settings
from app.database import MessageStore
from app.security import Vault


def reset_password() -> None:
    config = Settings()  # type: ignore[call-arg]
    store = MessageStore(config.database_path, Vault(config.encryption_key))
    store.initialize()
    store.ensure_bootstrap(config.admin_password, config.webhook_token)
    first = getpass.getpass("New admin password: ")
    second = getpass.getpass("Confirm new admin password: ")
    if len(first) < 8:
        raise SystemExit("Password must contain at least 8 characters.")
    if first != second:
        raise SystemExit("Passwords do not match.")
    store.reset_admin_password(first)
    print("Admin password updated. Existing sessions are invalid.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Local SMS Forwarder administration")
    parser.add_argument("command", choices=["reset-password"])
    args = parser.parse_args()
    if args.command == "reset-password":
        reset_password()


if __name__ == "__main__":
    main()
