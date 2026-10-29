"""SQLite storage layer (WAL mode, thread-safe)."""
import os
import sqlite3
import threading
import hashlib
import secrets
import datetime
import json
from typing import Any, Dict, List, Optional, Tuple

import config

_lock = threading.RLock()
lock = _lock            # public alias used by other modules
_conn: Optional[sqlite3.Connection] = None


def now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def today_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


def now_epoch() -> float:
    return datetime.datetime.now(datetime.timezone.utc).timestamp()


def iso_after(days: int, from_dt: Optional[datetime.datetime] = None) -> str:
    base = from_dt or datetime.datetime.now(datetime.timezone.utc)
    return (base + datetime.timedelta(days=days)).strftime("%Y-%m-%d")


def connect() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
        _conn = sqlite3.connect(config.DB_PATH, check_same_thread=False)
        _conn.row_factory = sqlite3.Row
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA synchronous=NORMAL")
        _conn.execute("PRAGMA foreign_keys=ON")
    return _conn


# ---------------------------------------------------------------- schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  username TEXT PRIMARY KEY,
  pass_hash TEXT NOT NULL,
  subscriber_name TEXT,
  email TEXT, phone TEXT,
  district TEXT, mandal TEXT, village_name TEXT,
  referral_username TEXT,
  device_id TEXT, device_bound_at TEXT,
  must_change INTEGER NOT NULL DEFAULT 0,
  access_granted INTEGER NOT NULL DEFAULT 0,
  blocked INTEGER NOT NULL DEFAULT 0,
  trial_start TEXT, trial_end TEXT,
  subscription_expiry TEXT,
  created_at TEXT NOT NULL,
  last_seen TEXT
);
CREATE TABLE IF NOT EXISTS villages(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  v_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  slug TEXT UNIQUE NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_villages(
  username TEXT NOT NULL,
  v_code TEXT NOT NULL,
  allotted_at TEXT NOT NULL,
  PRIMARY KEY(username, v_code)
);
CREATE TABLE IF NOT EXISTS sessions(
  token TEXT PRIMARY KEY,
  refresh_token TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL,
  device_id TEXT,
  created_at TEXT NOT NULL,
  access_expires TEXT NOT NULL,
  refresh_expires TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS plans(
  plan_id TEXT PRIMARY KEY,
  plan_name TEXT NOT NULL,
  plan_details TEXT,
  upfront_amount REAL NOT NULL,
  duration_days INTEGER NOT NULL DEFAULT 365,
  button_order INTEGER NOT NULL DEFAULT 1,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS portal_sessions(
  token TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  plan_id TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  last_status_seen TEXT
);
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  plan_id TEXT,
  amount REAL,
  status TEXT NOT NULL DEFAULT 'pending',
  portal_token TEXT,
  utr TEXT,
  proof_note TEXT,
  requested_at TEXT,
  confirmed_at TEXT,
  confirmed_by TEXT
);
CREATE TABLE IF NOT EXISTS settings(
  key TEXT PRIMARY KEY,
  value TEXT
);
CREATE TABLE IF NOT EXISTS sync_state(
  v_code TEXT NOT NULL,
  module TEXT NOT NULL,
  record_id TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 0,
  updated_by TEXT,
  updated_at TEXT,
  PRIMARY KEY(v_code, module, record_id)
);
CREATE TABLE IF NOT EXISTS sync_ops(
  op_id TEXT PRIMARY KEY,
  v_code TEXT, module TEXT, record_id TEXT, operation TEXT,
  username TEXT, device_id TEXT, applied_at TEXT
);
CREATE TABLE IF NOT EXISTS release_notes(
  version TEXT PRIMARY KEY, title TEXT, notes TEXT, date TEXT
);
CREATE TABLE IF NOT EXISTS videos(
  video_id TEXT PRIMARY KEY, title TEXT, description TEXT,
  video_link TEXT, download_url TEXT, mime_type TEXT,
  file_size INTEGER, version TEXT, category TEXT, language TEXT,
  sort_order INTEGER, enabled INTEGER
);
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT, feedback TEXT, rating INTEGER, app_version TEXT,
  device TEXT, device_id TEXT, created_at TEXT
);
CREATE TABLE IF NOT EXISTS devices(
  device_id TEXT PRIMARY KEY,
  username TEXT,
  bound_at TEXT, first_seen TEXT, last_seen TEXT,
  blocked_until TEXT
);
"""

DEFAULT_SETTINGS: Dict[str, str] = {
    "update_latest_version": "1.7.0",
    "update_latest_version_code": "42",
    "update_force": "0",
    "support_how_to_use": "1) Login with the username and temp password. 2) Open your village. "
                         "3) Use the floating panel to search LPM numbers, fill e-Crop forms, run eKYC "
                         "and send WhatsApp/SMS. 4) Sync Center keeps everything safe offline.",
    "support_faq": "Q: Payment done but not active? A: Send the screenshot on Telegram; the admin "
                   "approves within a few hours.\nQ: Which permissions? A: Accessibility, overlay and "
                   "mock-location (Developer Options) are needed for automation.",
    "support_contact_email": "support@yourdomain.example",
    "support_contact_phone": "+91-00000-00000",
    "telegram_link": config.TELEGRAM_LINK,
    "upi_id": config.UPI_ID,
    "upi_name": config.UPI_NAME,
    "trial_days": str(config.TRIAL_DAYS_DEFAULT),
}

DEFAULT_PLANS: List[Dict[str, Any]] = [
    {"plan_id": "plan_year", "plan_name": "Full Year Access",
     "plan_details": "All features • Offline sync • Automation engine • Updates for 365 days",
     "upfront_amount": 1999.0, "duration_days": 365, "button_order": 1, "enabled": 1},
    {"plan_id": "plan_quarter", "plan_name": "3-Month Access",
     "plan_details": "All features for 90 days", "upfront_amount": 599.0,
     "duration_days": 90, "button_order": 2, "enabled": 1},
]


def init_db() -> None:
    conn = connect()
    with _lock:
        conn.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            conn.execute(
                "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))
        if conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0] == 0:
            for p in DEFAULT_PLANS:
                conn.execute(
                    "INSERT INTO plans(plan_id,plan_name,plan_details,upfront_amount,"
                    "duration_days,button_order,enabled) VALUES(?,?,?,?,?,?,?)",
                    (p["plan_id"], p["plan_name"], p["plan_details"],
                     p["upfront_amount"], p["duration_days"], p["button_order"], p["enabled"]))
        conn.commit()


# ---------------------------------------------------------------- helpers
def q(sql: str, args: Tuple[Any, ...] = ()) -> List[sqlite3.Row]:
    conn = connect()
    with _lock:
        return conn.execute(sql, args).fetchall()


def q1(sql: str, args: Tuple[Any, ...] = ()) -> Optional[sqlite3.Row]:
    conn = connect()
    with _lock:
        return conn.execute(sql, args).fetchone()


def ex(sql: str, args: Tuple[Any, ...] = ()) -> int:
    conn = connect()
    with _lock:
        cur = conn.execute(sql, args)
        conn.commit()
        return cur.lastrowid


# ---------------------------------------------------------------- users
def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256",
                            password.encode("utf-8"), salt, config.ADMIN_PASSWORD_SALT_ROUNDS)
    return salt.hex() + "$" + h.hex()


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split("$", 1)
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                bytes.fromhex(salt_hex), config.ADMIN_PASSWORD_SALT_ROUNDS)
        return secrets.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def get_user(username: str) -> Optional[dict]:
    row = q1("SELECT * FROM users WHERE username=?", (str(username or "").strip().lower(),))
    return dict(row) if row else None


def temp_password() -> str:
    return "Temp@" + secrets.token_hex(4).upper()   # e.g. Temp@A1B2C3D4


def put_settings(update: Dict[str, str]) -> None:
    conn = connect()
    with _lock:
        for k, v in update.items():
            conn.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, str(v)))
        conn.commit()


def get_setting(key: str, default: str = "") -> str:
    row = q1("SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


def user_villages(username: str, base_url: str) -> List[dict]:
    rows = q("""SELECT v.v_code, v.name, v.slug FROM user_villages uv
                JOIN villages v ON v.v_code = uv.v_code AND v.enabled=1
                WHERE uv.username=? ORDER BY v.v_code""", (username,))
    out = []
    for r in rows:
        out.append({"name": r["name"], "vCode": r["v_code"],
                    "url": village_url(r["slug"], base_url)})
    return out


def village_url(slug: str, base_url: str) -> str:
    return base_url.rstrip("/") + "/app/" + slug + "/"


def to_json_dict(row: sqlite3.Row) -> dict:
    return json.loads(json.dumps(dict(row), default=str))
