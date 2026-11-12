"""Bootstrap an admin out-of-band:  NOTES_JWT_SECRET=... python -m app.cli create-admin <username>
Admins can never be created through the public API."""
import getpass
import sys

from .config import Settings
from .db import init_db, insert_user
from .schemas import RegisterIn
from .security import hash_password


def main(argv=None) -> int:
    argv = argv or sys.argv[1:]
    if len(argv) != 2 or argv[0] != "create-admin":
        print("usage: python -m app.cli create-admin <username>")
        return 2
    s = Settings.from_env()
    pw = getpass.getpass("Password: ")
    RegisterIn(username=argv[1], password=pw)          # same validation as the API
    init_db(s.db_path)
    insert_user(s.db_path, argv[1], hash_password(pw), role="admin")
    print("admin created")
    return 0


if __name__ == "__main__":
    sys.exit(main())
