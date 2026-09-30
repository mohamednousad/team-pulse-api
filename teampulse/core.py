"""Configuration, database access and security helpers."""
import hashlib
import hmac
import os
import secrets
import time

import jwt
from pymongo import ASCENDING, MongoClient

MONGODB_URI = os.environ.get("MONGODB_URI", "")
DB_NAME = os.environ.get("MONGODB_DB", "teampulse")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "60"))

TOKEN_TTL = 12 * 3600          # dashboard session length
ONLINE_WINDOW = 120            # seconds without a sync before a device counts as offline
CODE_TTL = 72 * 3600           # activation code lifetime
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no look-alike characters

_db = None
_ready = False


def get_db():
    """Return the database, creating the client and indexes once per process."""
    global _db, _ready
    if _db is None:
        if not MONGODB_URI:
            raise RuntimeError("MONGODB_URI is not set")
        _db = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000, maxPoolSize=5)[DB_NAME]
    if not _ready:
        _init(_db)
        _ready = True
    return _db


def _init(db):
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.employees.create_index([("token_hash", ASCENDING)], unique=True, sparse=True)
    db.employees.create_index([("code_hash", ASCENDING)], sparse=True)
    db.events.create_index([("emp", ASCENDING), ("s", ASCENDING)], unique=True)
    db.events.create_index([("created", ASCENDING)], expireAfterSeconds=RETENTION_DAYS * 86400)
    _bootstrap_admin(db)


def _bootstrap_admin(db):
    """Create the first admin from environment variables if none exists yet."""
    email = os.environ.get("ADMIN_EMAIL", "").strip().lower()
    password = os.environ.get("ADMIN_PASSWORD", "")
    if email and password and db.users.find_one({"role": "admin"}) is None:
        db.users.insert_one({
            "name": "Administrator", "email": email, "pw": hash_password(password),
            "role": "admin", "team": "", "created": int(time.time()),
        })


# ---- passwords, tokens, codes ------------------------------------------------

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, digest = stored.split("$")
        calc = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(calc, bytes.fromhex(digest))
    except (ValueError, TypeError):
        return False


_dummy = None


def burn_password_check(password: str) -> None:
    """Spend the same time as a real check so unknown emails are not distinguishable."""
    global _dummy
    if _dummy is None:
        _dummy = hash_password("dummy-password")
    verify_password(password, _dummy)


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def new_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def normalize_code(code: str) -> str:
    return code.upper().replace("-", "").replace(" ", "")


def make_jwt(user: dict) -> str:
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    payload = {"sub": str(user["_id"]), "exp": int(time.time()) + TOKEN_TTL}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def read_jwt(token: str) -> str | None:
    """Return the user id inside a valid token, or None."""
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not set")
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])["sub"]
    except (jwt.PyJWTError, KeyError):
        return None
