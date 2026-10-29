"""Request verification + session tokens.

The patched client signs exactly like the original one did:
  body = canonicalJSON(action,apiKey,deviceId,token?,...,clientHmacCheck,tamperFlags)
       + [,"signature":"<hex>"]  inside the closing brace
  signature = HMAC_SHA256(canonical, HMAC_SECRET).lowercase hex
  clientHmacCheck = HMAC_SHA256("LPM_NAV_HMAC_CHECK_V1", HMAC_SECRET).lowercase hex
We verify by byte-exact reconstruction of the canonical string.
"""
import hashlib
import hmac
import json
import re
import secrets
import datetime
from typing import Optional, Tuple

import config
from db import connect, ex, q1, now_iso, lock  # lock re-exported for sessions

_SIG_TAIL = re.compile(r',"signature":"([0-9a-fA-F:-]+)"}\s*$')


def _hmac_hex(message: str, key: str) -> str:
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()


def expected_client_hmac_check() -> str:
    return _hmac_hex(config.CLIENT_HMAC_MESSAGE, config.HMAC_SECRET)


def verify_request(body: str) -> Tuple[bool, str, dict]:
    """Returns (ok, reason, fields). Body still used verbatim for canonical check."""
    try:
        fields = json.loads(body)
    except Exception:
        return False, "bad_json", {}
    if not isinstance(fields, dict):
        return False, "bad_json", {}
    if fields.get("apiKey") != config.API_KEY:
        return False, "invalid_api_key", {}
    m = _SIG_TAIL.search(body)
    if not m:
        if not config.ALLOW_UNSIGNED_DEFAULT:
            return False, "missing_signature", fields
        return True, "unsigned(dev)", fields
    sent_sig = m.group(1).strip().lower()
    canonical = body[: m.start()] + "}"
    want = _hmac_hex(canonical, config.HMAC_SECRET)
    if not hmac.compare_digest(sent_sig, want.lower()):
        return False, "invalid_signature", fields
    chc = str(fields.get("clientHmacCheck", "")).strip().lower()
    want_chc = expected_client_hmac_check()
    if chc and not hmac.compare_digest(chc, want_chc):
        return False, "invalid_signature", fields
    return True, "ok", fields


# ------------------------------------------------------------------ tokens
def _no_lock_reexport(obj=None) -> None:  # keeps import surface obvious
    return None


def issue_session(username: str, device_id: str) -> dict:
    import db as _db
    token = "at_" + secrets.token_hex(24)
    refresh = "rt_" + secrets.token_hex(24)
    now = now_iso()
    acc_exp = (datetime.datetime.utcnow() +
               datetime.timedelta(minutes=config.ACCESS_TOKEN_MINUTES)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    ref_exp = (datetime.datetime.utcnow() + datetime.timedelta(days=config.REFRESH_TOKEN_DAYS)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    with _db._lock:
        conn = connect()
        conn.execute("INSERT INTO sessions(token,refresh_token,username,device_id,created_at,"
                     "access_expires,refresh_expires,revoked) VALUES(?,?,?,?,?,?,?,0)",
                     (token, refresh, username, device_id, now, acc_exp, ref_exp))
        conn.commit()
    return {"token": token, "refreshToken": refresh,
            "accessExpiresAt": acc_exp, "refreshExpiresAt": ref_exp}


def rotate_session(old_token: str, old_refresh: str, device_id: str) -> Tuple[bool, Optional[dict], str]:
    row = q1("SELECT * FROM sessions WHERE token=? AND revoked=0", (old_token,))
    if not row:
        return False, None, "token_expired"
    if row["revoked"] or not secrets.compare_digest(row["refresh_token"], old_refresh or ""):
        return False, None, "refresh_expired"
    if datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ") > row["refresh_expires"]:
        return False, None, "refresh_expired"
    if device_id and row["device_id"] and row["device_id"] != device_id:
        return False, None, "device_mismatch"
    new = issue_session(row["username"], row["device_id"])
    ex("UPDATE sessions SET revoked=1 WHERE token=?", (old_token,))
    return True, {"token": new["token"], "refreshToken": new["refreshToken"],
                  "username": row["username"]}, "ok"


def valid_access_token(token: str) -> Optional[dict]:
    if not token:
        return None
    row = q1("SELECT * FROM sessions WHERE token=? AND revoked=0", (token,))
    if not row:
        return None
    if datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ") > row["access_expires"]:
        return None
    return dict(row)
