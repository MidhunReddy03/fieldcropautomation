"""Admin console API — X-Admin-Key guarded. The user's access-control cockpit."""
import datetime
import json
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request

import config
import db
from db import (ex, get_setting, get_user, hash_password, iso_after, now_iso, q, q1,
                temp_password, today_iso)

router = APIRouter(prefix="/admin/api")


def _guard(x_admin_key: Optional[str]) -> None:
    if x_admin_key != config.ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Admin key required")


async def _json(request: Request) -> dict:
    body = await request.body()
    try:
        return json.loads(body.decode("utf-8")) if body else {}
    except Exception:
        return {}


def _user_state(u: dict) -> dict:
    import actions
    info = actions.compute_account_state(u, "")
    return {"username": u["username"], "name": u["subscriber_name"], "email": u["email"],
            "phone": u["phone"], "district": u["district"], "mandal": u["mandal"],
            "villageName": u["village_name"], "referral": u["referral_username"],
            "deviceId": u["device_id"],
            "mustChange": u["must_change"] == 1,
            "accessGranted": u["access_granted"] == 1,
            "blocked": u["blocked"] == 1,
            "trialEnd": u["trial_end"], "subscriptionExpiry": u["subscription_expiry"],
            "accountState": info["accountState"],
            "villages": [v["vCode"] for v in info["villages"]],
            "createdAt": u["created_at"], "lastSeen": u["last_seen"]}


@router.get("/users")
def users(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    rows = q("SELECT * FROM users ORDER BY created_at DESC")
    return {"users": [_user_state(dict(r)) for r in rows]}


@router.get("/user/{username}")
def user_detail(username: str, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    u = get_user(username)
    if not u:
        raise HTTPException(404, "no user")
    d = _user_state(u)
    d["payments"] = [dict(r) for r in q(
        "SELECT * FROM payments WHERE username=? ORDER BY id DESC", (username,))]
    d["portalSessions"] = [dict(r) for r in q(
        "SELECT * FROM portal_sessions WHERE username=? ORDER BY created_at DESC", (username,))]
    d["sessions"] = [dict(r) for r in q(
        "SELECT token,refresh_token,device_id,created_at,access_expires,refresh_expires,revoked "
        "FROM sessions WHERE username=?", (username,))]
    return d


def _require_user(username: str) -> None:
    if not get_user(username):
        raise HTTPException(404, "no user")


@router.post("/user/set_access")
async def set_access(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    ex("UPDATE users SET access_granted=? WHERE username=?",
       (1 if b.get("access") else 0, b["username"]))
    return {"status": "ok"}


@router.post("/user/set_blocked")
async def set_blocked(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    ex("UPDATE users SET blocked=? WHERE username=?",
       (1 if b.get("blocked") else 0, b["username"]))
    return {"status": "ok"}


@router.post("/user/extend")
async def extend(request: Request, x_admin_key: Optional[str] = Header(None)):
    """Extend subscription by N days from max(today, current expiry)."""
    _guard(x_admin_key); b = await _json(request)
    u = get_user(b["username"])
    if not u:
        raise HTTPException(404, "no user")
    today = today_iso()
    base = u["subscription_expiry"] or ""
    if not base or base < today:
        base = today
    new = (datetime.datetime.strptime(base, "%Y-%m-%d") +
           datetime.timedelta(days=int(b.get("days") or 30))).strftime("%Y-%m-%d")
    ex("UPDATE users SET subscription_expiry=?, access_granted=1 WHERE username=?",
       (new, b["username"]))
    return {"status": "ok", "subscriptionExpiry": new}


@router.post("/user/set_expiry")
async def set_expiry(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    ex("UPDATE users SET subscription_expiry=?, access_granted=1 WHERE username=?",
       (b["date"], b["username"]))
    return {"status": "ok"}


@router.post("/user/set_trial")
async def set_trial(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    days = int(b.get("days") or 0)
    if days <= 0:
        ex("UPDATE users SET trial_start=NULL, trial_end=NULL WHERE username=?",
           (b["username"],))
    else:
        ex("UPDATE users SET trial_start=?, trial_end=? WHERE username=?",
           (today_iso(), iso_after(days), b["username"]))
    return {"status": "ok"}


@router.post("/user/reset_password")
async def reset_password(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    tp = temp_password()
    ex("UPDATE users SET pass_hash=?, must_change=1 WHERE username=?",
       (hash_password(tp), b["username"]))
    return {"status": "ok", "tempPassword": tp}


@router.post("/user/unbind_device")
async def unbind_device(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    ex("UPDATE users SET device_id=NULL, device_bound_at=NULL WHERE username=?",
       (b["username"],))
    return {"status": "ok"}


@router.post("/user/delete")
async def delete_user(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM users WHERE username=?", (b["username"],))
    ex("DELETE FROM user_villages WHERE username=?", (b["username"],))
    ex("DELETE FROM sessions WHERE username=?", (b["username"],))
    return {"status": "ok"}


@router.post("/user/allot_village")
async def allot_village(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    _require_user(b["username"])
    if not q1("SELECT v_code FROM villages WHERE v_code=?", (b["v_code"],)):
        raise HTTPException(404, "no village")
    ex("INSERT OR IGNORE INTO user_villages(username,v_code,allotted_at) VALUES(?,?,?)",
       (b["username"], b["v_code"], now_iso()))
    return {"status": "ok"}


@router.post("/user/revoke_village")
async def revoke_village(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM user_villages WHERE username=? AND v_code=?",
       (b["username"], b["v_code"]))
    return {"status": "ok"}


# ------------------------------------------------------------------ payments
@router.post("/payments/approve")
async def approve_payment(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    pay = q1("SELECT * FROM payments WHERE id=?", (int(b["id"]),))
    if not pay:
        raise HTTPException(404, "no payment")
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (pay["plan_id"],))
    days = int(plan["duration_days"]) if plan else int(b.get("days") or 365)
    username = pay["username"]
    u = get_user(username)
    today = today_iso()
    base = (u["subscription_expiry"] or "") if u else ""
    if not base or base < today:
        base = today
    new = (datetime.datetime.strptime(base, "%Y-%m-%d") +
           datetime.timedelta(days=days)).strftime("%Y-%m-%d")
    now = now_iso()
    ex("UPDATE payments SET status='confirmed', confirmed_at=?, confirmed_by='admin' WHERE id=?",
       (now, pay["id"]))
    if pay["portal_token"]:
        ex("UPDATE portal_sessions SET status='completed' WHERE token=?", (pay["portal_token"],))
    if u:
        ex("UPDATE users SET subscription_expiry=?, access_granted=1 WHERE username=?",
           (new, username))
    return {"status": "ok", "username": username, "subscriptionExpiry": new,
            "planId": pay["plan_id"], "amount": pay["amount"]}


@router.post("/payments/reject")
async def reject_payment(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("UPDATE payments SET status='rejected', confirmed_at=?, confirmed_by='admin' WHERE id=?",
       (now_iso(), int(b["id"])))
    return {"status": "ok"}


@router.post("/payments/create")
async def create_manual_payment(request: Request, x_admin_key: Optional[str] = Header(None)):
    """Admin received the money directly on Telegram — record it without the portal."""
    _guard(x_admin_key); b = await _json(request)
    username = b["username"]
    _require_user(username)
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (b.get("planId") or "plan_year",))
    ex("INSERT INTO payments(username,plan_id,amount,status,utr,proof_note,requested_at) "
       "VALUES(?,?,?,'pending',?,?,?)",
       (username, plan["plan_id"] if plan else None,
        plan["upfront_amount"] if plan else b.get("amount", 0),
        b.get("utr") or "telegram-direct", b.get("note") or "manual", now_iso()))
    return {"status": "ok", "message": "Pending payment created — approve next"}


@router.get("/payments")
def payments(x_admin_key: Optional[str] = Header(None), status: str = ""):
    _guard(x_admin_key)
    if status:
        rows = q("SELECT * FROM payments WHERE status=? ORDER BY id DESC", (status,))
    else:
        rows = q("SELECT * FROM payments ORDER BY id DESC")
    return {"payments": [dict(r) for r in rows]}


# ------------------------------------------------------------------ villages
@router.get("/villages")
def villages_list(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"villages": [dict(r) for r in q("SELECT * FROM villages ORDER BY v_code")]}


@router.get("/plans")
def plans_list(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"plans": [dict(r) for r in q("SELECT * FROM plans ORDER BY button_order")]}


@router.get("/videos")
def videos_list(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"videos": [dict(r) for r in q("SELECT * FROM videos ORDER BY sort_order")]}


@router.get("/notes")
def notes_list(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"notes": [dict(r) for r in q("SELECT * FROM release_notes ORDER BY version DESC")]}


@router.post("/villages/save")
async def village_save(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    vcode = str(b["v_code"]).strip()
    name = str(b["name"]).strip()
    slug = str(b.get("slug") or "").strip().lower().replace(" ", "-") or vcode.lower()
    enabled = 1 if b.get("enabled", True) else 0
    if q1("SELECT id FROM villages WHERE v_code=?", (vcode,)):
        ex("UPDATE villages SET name=?, slug=?, enabled=? WHERE v_code=?",
           (name, slug, enabled, vcode))
    else:
        ex("INSERT INTO villages(v_code,name,slug,enabled,created_at) VALUES(?,?,?,?,?)",
           (vcode, name, slug, enabled, now_iso()))
    return {"status": "ok", "url": f"/app/{slug}/"}


@router.post("/villages/delete")
async def village_delete(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM villages WHERE v_code=?", (b["v_code"],))
    ex("DELETE FROM user_villages WHERE v_code=?", (b["v_code"],))
    return {"status": "ok"}


@router.post("/villages/allotments")
@router.get("/villages/allotments")
async def allotments(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"rows": [dict(r) for r in q(
        "SELECT uv.username, uv.v_code, uv.allotted_at, u.subscriber_name "
        "FROM user_villages uv LEFT JOIN users u ON u.username=uv.username "
        "ORDER BY uv.username")]}


# ------------------------------------------------------------------ content
@router.post("/plans/save")
async def plan_save(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("""INSERT INTO plans(plan_id,plan_name,plan_details,upfront_amount,duration_days,
          button_order,enabled) VALUES(?,?,?,?,?,?,?)
          ON CONFLICT(plan_id) DO UPDATE SET plan_name=excluded.plan_name,
          plan_details=excluded.plan_details, upfront_amount=excluded.upfront_amount,
          duration_days=excluded.duration_days, button_order=excluded.button_order,
          enabled=excluded.enabled""",
       (b["plan_id"], b["plan_name"], b.get("plan_details") or "",
        float(b.get("upfront_amount") or 0), int(b.get("duration_days") or 365),
        int(b.get("button_order") or 1), 1 if b.get("enabled", True) else 0))
    return {"status": "ok"}


@router.post("/plans/delete")
async def plan_delete(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM plans WHERE plan_id=?", (b["plan_id"],))
    return {"status": "ok"}


@router.post("/videos/save")
async def video_save(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("""INSERT INTO videos(video_id,title,description,video_link,download_url,mime_type,
          file_size,version,category,language,sort_order,enabled)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(video_id) DO UPDATE SET title=excluded.title,
          description=excluded.description, video_link=excluded.video_link,
          download_url=excluded.download_url, mime_type=excluded.mime_type,
          file_size=excluded.file_size, version=excluded.version, category=excluded.category,
          language=excluded.language, sort_order=excluded.sort_order,
          enabled=excluded.enabled""",
       (b["video_id"], b.get("title"), b.get("description"),
        b.get("video_link"), b.get("download_url"), b.get("mime_type") or "video/mp4",
        int(b.get("file_size") or 0), b.get("version"), b.get("category"),
        b.get("language"), int(b.get("sort_order") or 1),
        1 if b.get("enabled", True) else 0))
    return {"status": "ok"}


@router.post("/videos/delete")
async def video_delete(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM videos WHERE video_id=?", (b["video_id"],))
    return {"status": "ok"}


@router.post("/notes/save")
async def note_save(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("""INSERT INTO release_notes(version,title,notes,date) VALUES(?,?,?,?)
          ON CONFLICT(version) DO UPDATE SET title=excluded.title, notes=excluded.notes,
          date=excluded.date""",
       (b["version"], b.get("title"), b.get("notes"), b.get("date") or today_iso()))
    return {"status": "ok"}


@router.post("/notes/delete")
async def note_delete(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    ex("DELETE FROM release_notes WHERE version=?", (b["version"],))
    return {"status": "ok"}


# ------------------------------------------------------------------ settings/other
@router.get("/settings")
def settings_all(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"settings": {r["key"]: r["value"] for r in q("SELECT * FROM settings")}}


@router.post("/settings")
async def settings_save(request: Request, x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key); b = await _json(request)
    db.put_settings({k: str(v) for k, v in (b.get("values") or {}).items()})
    return {"status": "ok"}


@router.get("/feedback")
def feedback_all(x_admin_key: Optional[str] = Header(None)):
    _guard(x_admin_key)
    return {"feedback": [dict(r) for r in q("SELECT * FROM feedback ORDER BY id DESC LIMIT 500")]}


@router.get("/sync/browse")
def sync_browse(x_admin_key: Optional[str] = Header(None), v_code: str = "",
                module: str = "", limit: int = 200):
    _guard(x_admin_key)
    sql = "SELECT * FROM sync_state WHERE 1=1"
    args: list = []
    if v_code:
        sql += " AND v_code=?"
        args.append(v_code)
    if module:
        sql += " AND module=?"
        args.append(module)
    sql += " LIMIT ?"
    args.append(min(limit, 1000))
    return {"records": [dict(r) for r in q(sql, tuple(args))]}
