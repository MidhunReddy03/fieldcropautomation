"""Action handlers: auth, subscription, content. Exact JSON contract, see docs/BACKEND_CONTRACT.md"""
import datetime
import secrets
from typing import Any, Dict, Optional

import config
import security
from db import (ex, get_setting, get_user, hash_password, iso_after, now_iso, q, q1,
                temp_password, today_iso, user_villages, verify_password)

HAS_V_TOKEN = ("token",)


# ----------------------------------------------------------------- state machine
def pending_payment(username: str) -> Optional[dict]:
    row = q1("SELECT * FROM payments WHERE username=? AND status='pending' "
             "ORDER BY id DESC LIMIT 1", (username,))
    return dict(row) if row else None


def compute_account_state(user: dict, base_url: str) -> Dict[str, Any]:
    """Single source of truth for the paywall state machine."""
    from db import village_url  # late import keeps config pluggable
    username = user["username"]
    villages = user_villages(username, base_url)
    now = today_iso()
    sub_exp = user["subscription_expiry"]
    trial_end = user["trial_end"]
    state = ""
    access = user["access_granted"] == 1
    if pending_payment(username):
        state = "payment_pending"
    elif sub_exp and sub_exp >= now:
        state = ("active" if villages else "awaiting_village") if access else "subscription_required"
    elif sub_exp and sub_exp < now:
        state = "expired"      # renewal flow — independent of the access switch
    elif trial_end and trial_end >= now:
        state = "trial_active" if access else "subscription_required"
    else:
        state = "subscription_required"
    return {
        "accountState": state,
        "villages": villages,
        "trialEndsAt": trial_end or None,
        "subscriptionExpiryDate": sub_exp or None,
        "hasAccess": user["access_granted"] == 1,
        "blocked": user["blocked"] == 1,
    }


def touch_login(user: dict, device_id: str) -> None:
    stamp = now_iso()
    ex("UPDATE users SET last_seen=? WHERE username=?", (stamp, user["username"]))
    if device_id:
        found = q1("SELECT device_id FROM devices WHERE device_id=?", (device_id,))
        if not found:
            ex("INSERT INTO devices(device_id,username,first_seen,last_seen) VALUES(?,?,?,?)",
               (device_id, user["username"], stamp, stamp))
        else:
            ex("UPDATE devices SET last_seen=?, username=COALESCE(username,?) WHERE device_id=?",
               (stamp, user["username"], device_id))
    if user["device_id"] != device_id and device_id and not user["device_id"]:
        ex("UPDATE users SET device_id=?, device_bound_at=? WHERE username=?",
           (device_id, stamp, user["username"]))


# ------------------------------------------------------------------- auth actions
def h_login(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    password = str(fields.get("password") or "")
    device_id = str(fields.get("deviceId") or "")
    user = get_user(username)
    if not user or not verify_password(password, user["pass_hash"]):
        return {"status": "unauthorized", "message": "Wrong username or password"}
    if user["blocked"] == 1:
        return {"status": "blocked",
                "message": "Account blocked. Contact us on Telegram: " + _tg_link()}
    if user["device_id"] and user["device_id"] != device_id:
        return {"status": "device_mismatch",
                "message": "This account is already bound to another device. "
                           "Contact us on Telegram for a device reset."}
    touch_login(user, device_id)
    info = compute_account_state(user, base_url)
    sess = security.issue_session(username, device_id)
    villager_val = {v["vCode"]: v for v in info["villages"]}
    return {
        "status": "success",
        "token": sess["token"],
        "refreshToken": sess["refreshToken"],
        "masterAppUrl": None,
        "mustChange": bool(user["must_change"] == 1),
        "message": "Login ok",
        "villages": info["villages"],
        "accountState": info["accountState"],
        "trialEndsAt": info["trialEndsAt"],
        "subscriptionExpiryDate": info["subscriptionExpiryDate"],
        "_dbg_mapped": list(villager_val.keys()),
    }


def h_register_user(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    name = str(fields.get("subscriberName") or fields.get("name") or "").strip()
    email = str(fields.get("email") or "").strip()
    phone = str(fields.get("phoneNumber") or "").strip()
    district = str(fields.get("district") or "").strip()
    mandal = str(fields.get("mandal") or "").strip()
    village = str(fields.get("village") or "").strip()
    referral = str(fields.get("referralUsername") or "").strip().lower()

    if not username or len(username) < 3:
        return {"status": "forbidden", "message": "Valid username required"}
    if not name or not phone or not district or not mandal or not village:
        return {"status": "forbidden", "message": "All fields are required"}
    if get_user(username):
        return {"status": "duplicate_username",
                "message": "Username already exists. Pick another."}
    tp = temp_password()
    days = int(get_setting("trial_days", str(config.TRIAL_DAYS_DEFAULT)) or 0)
    trial_start, trial_end = (today_iso(), iso_after(days)) if days > 0 else (None, None)
    stamp = now_iso()
    ex("""INSERT INTO users(username,pass_hash,subscriber_name,email,phone,district,mandal,
          village_name,referral_username,must_change,access_granted,blocked,
          trial_start,trial_end,created_at) VALUES(?,?,?,?,?,?,?,?,?,1,1,0,?,?,?)""",
       (username, hash_password(tp), name, email, phone, district, mandal, village,
        referral or None, trial_start, trial_end, stamp))
    if referral and get_user(referral):
        ref = get_user(referral)
        base = ref["trial_end"] or today_iso()
        bonus = int(get_setting("referral_bonus_days", "3"))
        if ref["subscription_expiry"] and ref["subscription_expiry"] >= today_iso():
            base = ref["subscription_expiry"]
        from datetime import datetime as _dt
        nb = (_dt.strptime(base, "%Y-%m-%d") + datetime.timedelta(days=bonus)).strftime("%Y-%m-%d")
        if ref["subscription_expiry"] and ref["subscription_expiry"] >= today_iso():
            ex("UPDATE users SET subscription_expiry=? WHERE username=?", (nb, referral))
        else:
            ex("UPDATE users SET trial_end=? WHERE username=?", (nb, referral))
    return {"status": "registered", "message": "Registered. Save this password.",
            "username": username, "tempPassword": tp,
            "trialGranted": days > 0, "trialEndsAt": trial_end}


def h_request_password_reset(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    user = get_user(username)
    if not user:
        return {"status": "unauthorized", "message": "No such account"}
    tp = temp_password()
    ex("UPDATE users SET pass_hash=?, must_change=1 WHERE username=?",
       (hash_password(tp), username))
    return {"status": "updated", "message": "Temp password generated.",
            "username": username, "tempPassword": tp}


def h_change_password(fields: dict, base_url: str) -> dict:
    token = str(fields.get("token") or "")
    new_password = str(fields.get("newPassword") or "")
    session = security.valid_access_token(token)
    if not session:
        return {"status": "token_expired", "message": "Login again"}
    if len(new_password) < 6:
        return {"status": "forbidden", "message": "Password must be 6+ characters"}
    ex("UPDATE users SET pass_hash=?, must_change=0 WHERE username=?",
       (hash_password(new_password), session["username"]))
    return {"status": "updated", "message": "Password changed"}


def h_refresh_token(fields: dict, base_url: str) -> dict:
    ok, sess, reason = security.rotate_session(
        str(fields.get("token") or ""), str(fields.get("refreshToken") or ""),
        str(fields.get("deviceId") or ""))
    if not ok:
        return {"status": reason, "message": "Session expired, login again"}
    user = get_user(sess["username"])
    if not user:
        return {"status": "unauthorized", "message": "Account missing"}
    info = compute_account_state(user, base_url)
    return {"status": "success",
            "token": sess["token"], "refreshToken": sess["refreshToken"],
            "message": "Refreshed",
            "accountState": info["accountState"],
            "subscriptionExpiryDate": info["subscriptionExpiryDate"]}


def h_get_villages(fields: dict, base_url: str) -> dict:
    token = str(fields.get("token") or "")
    session = security.valid_access_token(token)
    if not session:
        return {"status": "token_expired", "message": "Login again"}
    user = get_user(session["username"])
    if not user:
        return {"status": "unauthorized", "message": "Account missing"}
    info = compute_account_state(user, base_url)
    return {"status": "success", "villages": info["villages"], "message": "Fetched",
            "accountState": info["accountState"],
            "subscriptionExpiryDate": info["subscriptionExpiryDate"],
            "trialEndsAt": info["trialEndsAt"]}


# -------------------------------------------------------------- subscription actions
def _plan_offer(plan: dict, username: str, base_url: str) -> dict:
    offer = {
        "planName": plan["plan_name"],
        "planDetails": plan["plan_details"],
        "upfrontAmount": plan["upfront_amount"],
        "planId": plan["plan_id"],
        "subscriptionId": plan["plan_id"] + "-" + (username or "guest"),
        "linkUrl": base_url.rstrip("/") + "/portal/start?plan=" + plan["plan_id"] +
                   (("&u=" + username) if username else ""),
        "buttonOrder": plan["button_order"],
        "enabled": bool(plan["enabled"]),
    }
    return offer


def h_get_subscription_offers(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    plans = q("SELECT * FROM plans WHERE enabled=1 ORDER BY button_order, plan_id")
    return {"status": "success", "message": "Offers",
            "offers": [_plan_offer(dict(p), username, base_url) for p in plans]}


def _new_portal_session(username: str, plan_id: str, hours: int = 2) -> dict:
    token = "ps_" + secrets.token_hex(16)
    stamp = now_iso()
    exp = (datetime.datetime.utcnow() + datetime.timedelta(hours=hours)).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    ex("INSERT INTO portal_sessions(token,username,plan_id,status,created_at,expires_at) "
       "VALUES(?,?,?,?,?,?)", (token, username, plan_id, "open", stamp, exp))
    return {"token": token, "expiresAt": exp}


def h_create_web_portal_session(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    plan_id = str(fields.get("planId") or "")
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (plan_id,))
    if not plan:
        return {"status": "fail", "message": "Unknown plan"}
    ps = _new_portal_session(username, plan_id)
    return {"status": "success", "message": "Opening payment page",
            "portalUrl": base_url.rstrip("/") + "/portal/" + ps["token"],
            "expiresAt": ps["expiresAt"], "preferredPlanId": plan_id}


def h_create_subscription_session(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    plan_id = str(fields.get("planId") or "")
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (plan_id,))
    if not plan:
        return {"status": "fail", "message": "Unknown plan"}
    ps = _new_portal_session(username, plan_id)
    return {"status": "success", "message": "Checkout",
            "checkoutUrl": base_url.rstrip("/") + "/portal/" + ps["token"],
            "subscriptionId": plan_id + "-" + username, "planId": plan_id,
            "planName": plan["plan_name"]}


def h_get_subscription_status(fields: dict, base_url: str) -> dict:
    username = str(fields.get("username") or "").strip().lower()
    user = get_user(username)
    if not user:
        return {"status": "unauthorized", "message": "No such account"}
    info = compute_account_state(user, base_url)
    pay = pending_payment(username)
    msg = "Under verification — approve on Telegram after sending proof" \
        if pay else "Status fetched"
    return {"status": "success", "message": msg,
            "accountState": info["accountState"],
            "subscriptionExpiryDate": info["subscriptionExpiryDate"]}


# ------------------------------------------------------------------ content actions
def h_get_support_info(fields: dict, base_url: str) -> dict:
    return {"status": "success",
            "how_to_use": get_setting("support_how_to_use"),
            "faq": get_setting("support_faq"),
            "contact_email": get_setting("support_contact_email"),
            "contact_phone": get_setting("support_contact_phone"),
            "message": None}


def h_check_update(fields: dict, base_url: str) -> dict:
    # Default mirrors the client's own versionCode (42) -> the app NEVER nags for
    # an update. Admin can override via settings: update_latest_version_code (43+)
    # plus update_apk_url, if you deliberately want to push a new build.
    return {"latestVersion": get_setting("update_latest_version", "1.7.0"),
            "latestVersionCode": int(get_setting("update_latest_version_code", "42") or 42),
            "apkUrl": get_setting("update_apk_url", config.UPDATE_APK_URL),
            "forceUpdate": get_setting("update_force", "0") == "1"}


def h_get_release_notes(fields: dict, base_url: str) -> dict:
    row = q1("SELECT * FROM release_notes ORDER BY version DESC LIMIT 1")
    if not row:
        return {"status": "fail", "message": "No release notes", "version": None,
                "title": None, "notes": None, "date": None}
    d = dict(row)
    return {"status": "success", "version": d["version"], "title": d["title"],
            "notes": d["notes"], "date": d["date"], "message": None}


def h_submit_feedback(fields: dict, base_url: str) -> dict:
    token = str(fields.get("token") or "")
    feedback = str(fields.get("feedback") or "").strip()
    if not feedback:
        return {"status": "empty_feedback", "message": "Write something first"}
    session = security.valid_access_token(token)
    username = session["username"] if session else None
    try:
        rating = int(fields.get("rating") or 0)
    except Exception:
        rating = 0
    ex("INSERT INTO feedback(username,feedback,rating,app_version,device,device_id,created_at) "
       "VALUES(?,?,?,?,?,?,?)",
       (username, feedback, rating, str(fields.get("appVersion") or ""),
        str(fields.get("device") or ""), str(fields.get("deviceId") or ""), now_iso()))
    return {"status": "updated", "message": "Thanks for the feedback!"}


def h_get_videos_catalog(fields: dict, base_url: str) -> dict:
    rows = q("SELECT * FROM videos WHERE enabled=1 ORDER BY sort_order, video_id")
    videos = []
    for r in rows:
        d = dict(r)
        videos.append({
            "videoId": d["video_id"], "title": d["title"], "description": d["description"],
            "videoLink": d["video_link"], "downloadUrl": d["download_url"],
            "mimeType": d["mime_type"] or "video/mp4", "fileSize": d["file_size"] or 0,
            "version": d["version"], "category": d["category"],
            "language": d["language"], "sortOrder": d["sort_order"],
            "enabled": bool(d["enabled"]),
        })
    return {"status": "success", "videos": videos}


def _tg_link() -> str:
    return get_setting("telegram_link", config.TELEGRAM_LINK)
