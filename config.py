"""Central config for the LPM-Replica backend.

Everything here is YOURS â€” replace placeholders before going public with users.
None of the original developer's secrets are used.
"""
import os

# ===== OWN API CREDENTIALS (new, independent of the original developer) =====
# The client APK will be patched to send exactly this apiKey.
API_KEY = "LPMBot23_apiKey_7f4KQ9R2X"
# New HMAC secret â€” the APK patch will embed these exact bytes.
HMAC_SECRET = "LPMReplica_2026_Fr3eTier_HMAC_Q7pR4tV8nZa2mK9x"

# Sentinel message the client signs for the client-side sanity check.
# Kept identical to the original connector so the patched APK needs no edit here.
CLIENT_HMAC_MESSAGE = "LPM_NAV_HMAC_CHECK_V1"

# Development build: accept unsigned/incorrectly-signed requests (curl testing, Wi-Fi phone tests).
# Set env LPM_ALLOW_UNSIGNED=0 (or delete this variable) for the production deployment.
ALLOW_UNSIGNED_DEFAULT = os.environ.get("LPM_ALLOW_UNSIGNED", "1") == "1"

# ===== Own runtime identity =====
APP_TITLE = "LPM Replica Backend"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "lpm.db")

# ===== Admin console =====
ADMIN_KEY = "FP-ADM-2026-Lsd4PPEhpL3jPQjxdgdbz3kQ95bz"     # login key for /admin/ â€” CHANGE THIS
ADMIN_PASSWORD_SALT_ROUNDS = 2_000_000     # pbkdf2 iterations

# ===== Business defaults (also editable live from the admin panel) =====
TRIAL_DAYS_DEFAULT = 0
ACCESS_TOKEN_MINUTES = 12 * 60
REFRESH_TOKEN_DAYS = 45
SYNC_PROTOCOL_VERSION = 3
YEARLY_RENEWAL_UPSELL = True

# ===== Telegram-manual-payment endpoints (PLACEHOLDERS â€” replace with yours) =====
TELEGRAM_LINK = "https://t.me/YOUR_TELEGRAM_HERE"
UPI_ID = "YOUR_UPI_ID@upi"
UPI_NAME = "YOUR PAYEE NAME"
UPI_NOTE = "LPM Service Payment"

# ===== App update feed (our own APK distribution; fill with GitHub Releases link) =====
UPDATE_APK_URL = ""   # blank = never suggest an update; set in admin settings only when you publish a real APK

# ===== Security limits =====
RATE_LIMIT_PER_MIN_PER_IP = 240
TEMP_BLOCK_MINUTES = 30
MAX_SYNC_OP_PAYLOAD = 4_194_304          # matches client-side 4 MiB op guard
MAX_SYNC_BATCH_TOTAL = 24_000_000        # ~12MB client journal cap x2 headroom
