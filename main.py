"""LPM-Replica backend entrypoint.

Serves:
  POST /exec                 the 16-action client contract
  POST /admin/api/*          your access-control cockpit
  /admin/                    admin console page
  /portal/start?plan&u       checkout entry (creates a portal session)
  /portal/{token}            UPI QR + Telegram-proof checkout page
  /api/village/{v_code}/*    REST for the village web app (village-token guarded)
  /app/{slug}/               the village web app itself (WebView target)
"""
import collections
import json
import time
from typing import Optional

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

import actions
import admin_api
import config
import db
import security
import sync as sync_mod
from db import ex, get_setting, get_user, now_iso, q, q1, village_url

app = FastAPI(title=config.APP_TITLE, docs_url=None, redoc_url=None)
app.include_router(admin_api.router, include_in_schema=False)

# ------------------------------------------------------------------ rate limiting
_hits: collections.defaultdict = collections.defaultdict(collections.deque)
_blocked_until: dict = {}


def _rpc_gate(ip: str) -> bool:
    now = time.time()
    until = _blocked_until.get(ip)
    if until and now < until:
        return False
    dq = _hits[ip]
    while dq and dq[0] < now - 60:
        dq.popleft()
    dq.append(now)
    if len(dq) > config.RATE_LIMIT_PER_MIN_PER_IP:
        _blocked_until[ip] = now + config.TEMP_BLOCK_MINUTES * 60
        return False
    return True


# ------------------------------------------------------------------ /exec
ACTION_HANDLERS = {
    "login": actions.h_login,
    "registerUser": actions.h_register_user,
    "requestPasswordReset": actions.h_request_password_reset,
    "changePassword": actions.h_change_password,
    "refreshToken": actions.h_refresh_token,
    "getVillages": actions.h_get_villages,
    "getSubscriptionOffers": actions.h_get_subscription_offers,
    "createWebPortalSession": actions.h_create_web_portal_session,
    "createSubscriptionSession": actions.h_create_subscription_session,
    "getSubscriptionStatus": actions.h_get_subscription_status,
    "getSupportInfo": actions.h_get_support_info,
    "checkUpdate": actions.h_check_update,
    "getReleaseNotes": actions.h_get_release_notes,
    "submitFeedback": actions.h_submit_feedback,
    "getVideosCatalog": actions.h_get_videos_catalog,
}
NO_TOKEN_ACTIONS = {"login", "refreshToken", "registerUser", "requestPasswordReset",
                    "getSubscriptionOffers", "createWebPortalSession",
                    "createSubscriptionSession", "getSubscriptionStatus",
                    "getSupportInfo", "checkUpdate", "getReleaseNotes", "getVideosCatalog"}


@app.post("/exec")
async def exec_router(request: Request):
    ip = request.client.host if request.client else "?"
    if not _rpc_gate(ip):
        return JSONResponse({"status": "temporarily_blocked",
                             "message": "Too many requests; try again shortly"})
    body = (await request.body()).decode("utf-8", "replace")
    ok, reason, fields = security.verify_request(body)
    if not ok:
        status = "invalid_signature" if "signature" in reason else "fail"
        return JSONResponse({"status": status, "message": "Request rejected: " + reason})
    action = str(fields.get("action") or "").strip()
    base_url = str(request.base_url).rstrip("/")

    if action == "globalSyncBatch":
        if not config.ALLOW_UNSIGNED_DEFAULT and reason == "unsigned(dev)":
            return JSONResponse({"status": "invalid_signature", "message": "signature required"})
        result = sync_mod.handle_global_sync(fields, base_url)
        return JSONResponse(result)

    handler = ACTION_HANDLERS.get(action)
    if handler is None:
        return JSONResponse({"status": "fail", "message": "Unknown action: " + action})
    if action not in NO_TOKEN_ACTIONS:
        token = str(fields.get("token") or "")
        session = security.valid_access_token(token)
        if not session:
            return JSONResponse({"status": "token_expired", "message": "Login again"})
        fields["__username"] = session["username"]
    try:
        result = handler(fields, base_url)
    except Exception as e:  # never leak stack traces to the client
        return JSONResponse({"status": "fail", "message": "Server error: " + str(e)})
    return JSONResponse(result)


@app.get("/exec")
async def exec_router_get(vCode: Optional[str] = None):
    """The original Apps-Script backend was opened by the CLIENT with GET for two
    flows the smali reconstructs as `ENDPOINT?vCode=<village vCode>`:
      - the village app WebView (MainActivity's saved village URL + renderer-recovery)
      - its 'open in browser' fallback (favicon.ico hits prove real browser opens)
    So a GET here must hand back the village app for that vCode, not 405."""
    code = (vCode or "").strip()
    if not code:
        return JSONResponse({"status": "fail",
                             "message": "This is the FieldPilot API. Use POST /exec."})
    row = q1("SELECT slug, v_code FROM villages WHERE v_code=? AND enabled=1", (code,))
    if not row:
        return JSONResponse({"status": "fail", "message": "Unknown village code: " + code})
    # The original served the village app HTML INLINE at this exact URL (no redirect):
    # the app's WebViewClient aborts any /exec?vCode= navigation that is redirected,
    # so we must respond 200 with the HTML directly. The injected __VSLUG prelude pins
    # the village identity because the HTML normally derives its slug from pathname.
    html = open("static/app/index.html", "r", encoding="utf-8").read()
    prelude = "<script>window.__VSLUG=" + json.dumps(row["slug"]) + ";</script>"
    html = html.replace("<head>", "<head>" + prelude, 1) if "<head>" in html else prelude + html
    return HTMLResponse(html)


# ------------------------------------------------------------------ health
@app.get("/healthz")
def healthz():
    n_users = q1("SELECT COUNT(*) AS n FROM users")["n"]
    n_villages = q1("SELECT COUNT(*) AS n FROM villages")["n"]
    return {"status": "ok", "users": n_users, "villages": n_villages,
            "apiKeyConfigured": bool(config.API_KEY),
            "allow_unsigned_dev": config.ALLOW_UNSIGNED_DEFAULT}


# ------------------------------------------------------------------ pages
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse("/admin/")


@app.get("/admin/", response_class=FileResponse)
@app.get("/admin", response_class=FileResponse)
def admin_page():
    return FileResponse("static/admin.html", media_type="text/html")


@app.get("/portal/start", response_class=HTMLResponse)
def portal_start_page(plan: str = "", u: str = ""):
    plan_row = q1("SELECT * FROM plans WHERE plan_id=? AND enabled=1", (plan,))
    if not plan_row:
        plans = q("SELECT * FROM plans WHERE enabled=1 ORDER BY button_order")
        items = "".join(
            f'<a class="btn" href="/portal/start?plan={p["plan_id"]}&u={u}">'
            f'{p["plan_name"]} — ₹{p["upfront_amount"]:.0f}</a><br>' for p in plans)
        return HTMLResponse(f"<h2>Choose a plan</h2>{items or 'No plans configured'}")
    p = dict(plan_row)
    uname = u
    return HTMLResponse(f"""<!doctype html><meta charset='utf-8'>
<title>Checkout</title><body style="font-family:sans-serif;max-width:420px;margin:40px auto">
<h2>Checkout — {p['plan_name']}</h2>
<p>{p['plan_details'] or ''}</p>
<p><b>₹{p['upfront_amount']:.0f}</b> for {p['duration_days']} days</p>
<label>Your username<br><input id='u' value='{uname}' style='width:100%;padding:10px'></label><br><br>
<button class="btn" onclick='go()' style="padding:12px 20px">Open payment page</button>
<pre id='err' style="color:#a00"></pre>
<script>
async function go(){{
  const r = await fetch('/portal/api/start', {{method:'POST', headers:{{'Content-Type':'application/json'}},
     body: JSON.stringify({{plan:'{plan}', username: document.getElementById('u').value}})}});
  const j = await r.json();
  if (j.url) location.href = j.url; else document.getElementById('err').textContent = j.detail || 'Failed';
}}
</script></body>""")


@app.post("/portal/api/start")
async def portal_api_start(request: Request):
    b = json.loads((await request.body()).decode("utf-8") or "{}")
    plan = str(b.get("plan") or "")
    username = str(b.get("username") or "").strip().lower()
    if not q1("SELECT 1 FROM plans WHERE plan_id=? AND enabled=1", (plan,)):
        return JSONResponse({"detail": "unknown plan"}, status_code=404)
    ps = actions._new_portal_session(username, plan, hours=int(get_setting("portal_hours", "6")))
    return {"token": ps["token"], "url": "/portal/" + ps["token"], "expiresAt": ps["expiresAt"]}


@app.get("/portal/{token}", response_class=FileResponse)
def portal_page(token: str):
    if not q1("SELECT token FROM portal_sessions WHERE token=?", (token,)):
        return HTMLResponse("This payment page has expired. Reopen the Checkout from the app.",
                            status_code=404)
    return FileResponse("static/portal.html", media_type="text/html")


@app.get("/portal/api/session/{token}")
def portal_api_session(token: str):
    ps = q1("SELECT * FROM portal_sessions WHERE token=?", (token,))
    if not ps:
        return JSONResponse({"detail": "expired"}, status_code=404)
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (ps["plan_id"],)) if ps["plan_id"] else None
    amount = float(plan["upfront_amount"]) if plan else 0.0
    upi_id = get_setting("upi_id", config.UPI_ID)
    upi_name = get_setting("upi_name", config.UPI_NAME)
    note = get_setting("upi_note", config.UPI_NOTE)
    intent = (f"upi://pay?pa={upi_id}&pn={upi_name}"
              + (f"&am={amount:.2f}" if amount > 0 else "")
              + f"&cu=INR&tn={note}%20{ps['username']}")
    pay = q1("SELECT * FROM payments WHERE portal_token=? ORDER BY id DESC LIMIT 1", (token,))
    from db import today_iso
    return {
        "username": ps["username"], "status": ps["status"],
        "plan": dict(plan) if plan else None,
        "amount": amount, "upiId": upi_id, "upiName": upi_name,
        "upiIntent": intent, "telegramLink": get_setting("telegram_link", config.TELEGRAM_LINK),
        "expiresAt": ps["expires_at"],
        "userAccountState": (actions.compute_account_state(
            get_user(ps["username"]), "").get("accountState") if get_user(ps["username"]) else None),
        "subscriptionExpiry": (get_user(ps["username"]) or {}).get("subscription_expiry"),
        "payment": dict(pay) if pay else None,
    }


@app.get("/portal/api/qr/{token}", response_class=Response)
def portal_qr(token: str):
    import segno
    ps = q1("SELECT * FROM portal_sessions WHERE token=?", (token,))
    if not ps:
        return JSONResponse({"detail": "expired"}, status_code=404)
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (ps["plan_id"],)) if ps["plan_id"] else None
    amount = float(plan["upfront_amount"]) if plan else 0.0
    upi_id = get_setting("upi_id", config.UPI_ID)
    upi_name = get_setting("upi_name", config.UPI_NAME)
    note = get_setting("upi_note", config.UPI_NOTE)
    intent = (f"upi://pay?pa={upi_id}&pn={upi_name}"
              + (f"&am={amount:.2f}" if amount > 0 else "")
              + f"&cu=INR&tn={note}%20{ps['username']}")
    from io import BytesIO
    buf = BytesIO()
    segno.make(intent).save(buf, kind="svg", scale=8, border=2)
    return Response(buf.getvalue().decode("utf-8"), media_type="image/svg+xml")


@app.post("/portal/api/claim")
async def portal_claim(request: Request):
    b = json.loads((await request.body()).decode("utf-8") or "{}")
    token = str(b.get("token") or "")
    ps = q1("SELECT * FROM portal_sessions WHERE token=?", (token,))
    if not ps:
        return JSONResponse({"detail": "expired"}, status_code=404)
    if ps["status"] == "completed":
        return {"status": "confirmed"}
    utr = str(b.get("utr") or "").strip()
    note_text = str(b.get("note") or "").strip()
    existing = q1("SELECT * FROM payments WHERE portal_token=? AND status IN ('pending')",
                  (token,))
    if existing:
        ex("UPDATE payments SET utr=?, proof_note=? WHERE id=?",
           (utr, note_text, existing["id"]))
        return {"status": "pending", "message": "Already recorded — admin will approve soon"}
    plan = q1("SELECT * FROM plans WHERE plan_id=?", (ps["plan_id"],)) if ps["plan_id"] else None
    ex("""INSERT INTO payments(username,plan_id,amount,status,portal_token,utr,proof_note,
          requested_at) VALUES(?,?,?,'pending',?,?,?,?)""",
       (ps["username"], ps["plan_id"], float(plan["upfront_amount"]) if plan else 0.0,
        token, utr, note_text, now_iso()))
    return {"status": "pending",
            "message": "Sent! Share the screenshot on Telegram; the admin approves it shortly."}


# ------------------------------------------------------------------ village app
def _village_slug_to_vcode(slug: str):
    row = q1("SELECT v_code, name FROM villages WHERE slug=? AND enabled=1", (slug,))
    return row if row else None


@app.get("/app/{slug}", response_class=FileResponse)
@app.get("/app/{slug}/", response_class=FileResponse)
@app.get("/app/{slug}/{rest:path}", response_class=FileResponse)
def village_app(slug: str, rest: Optional[str] = None):
    if not _village_slug_to_vcode(slug):
        return HTMLResponse("Unknown village app.", status_code=404)
    return FileResponse("static/app/index.html", media_type="text/html")


def _village_guard(request: Request) -> Optional[dict]:
    tok = request.headers.get("x-village-token", "")
    want = get_setting("village_token", config.ADMIN_KEY)
    if tok != want:
        return None
    return {"ok": True}


@app.get("/api/village/lookup/{slug}")
def village_lookup(slug: str):
    row = _village_slug_to_vcode(slug)
    if not row:
        return JSONResponse({"detail": "unknown"}, status_code=404)
    return {"vCode": row["v_code"], "name": row["name"]}


@app.get("/api/village/{v_code}")
def village_records(v_code: str, request: Request, module: str = ""):
    # Public read, exactly like the original: the village HTML and its data came
    # straight from the Apps-Script page with no token. The token guard stays on
    # the mutating endpoints below.
    sql = "SELECT * FROM sync_state WHERE v_code=?"
    args: list = [v_code]
    if module:
        sql += " AND module=?"
        args.append(module)
    sql += " ORDER BY module, record_id"
    rows = q(sql, tuple(args))
    out = {}
    for r in rows:
        try:
            payload = json.loads(r["payload_json"])
        except Exception:
            payload = {"_raw": r["payload_json"]}
        out.setdefault(r["module"], {})[r["record_id"]] = {"version": r["version"], "fields": payload}
    return {"status": "success", "vCode": v_code, "modules": out}


@app.post("/api/village/{v_code}/upsert")
async def village_upsert(v_code: str, request: Request):
    if not _village_guard(request):
        return JSONResponse({"detail": "village token required"}, status_code=401)
    b = json.loads((await request.body()).decode("utf-8") or "{}")
    module = str(b.get("module") or "")
    record_id = str(b.get("recordId") or "").strip()
    fields = b.get("changedFields") or {}
    base_version = int(b.get("baseVersion") or -1)
    if not module or not record_id:
        return JSONResponse({"detail": "module and recordId required"}, status_code=400)
    row = q1("SELECT * FROM sync_state WHERE v_code=? AND module=? AND record_id=?",
             (v_code, module, record_id))
    current = int(row["version"]) if row else 0
    if row is None:
        ex("INSERT INTO sync_state(v_code,module,record_id,payload_json,version,updated_by,"
           "updated_at) VALUES(?,?,?,?,'1',?,?)",
           (v_code, module, record_id, json.dumps(fields, ensure_ascii=False),
            "web-app", now_iso()))
        return {"status": "success", "version": 1}
    if base_version != current:
        return JSONResponse({"status": "VERSION_CONFLICT", "actualVersion": current},
                            status_code=409)
    merged = sync_mod._deep_merge(json.loads(row["payload_json"] or "{}"), fields)
    ex("UPDATE sync_state SET payload_json=?, version=version+1, updated_by=?, updated_at=? "
       "WHERE v_code=? AND module=? AND record_id=?",
       (json.dumps(merged, ensure_ascii=False), "web-app", now_iso(),
        v_code, module, record_id))
    return {"status": "success", "version": current + 1}


@app.post("/api/village/{v_code}/delete")
async def village_delete_record(v_code: str, request: Request):
    if not _village_guard(request):
        return JSONResponse({"detail": "village token required"}, status_code=401)
    b = json.loads((await request.body()).decode("utf-8") or "{}")
    ex("DELETE FROM sync_state WHERE v_code=? AND module=? AND record_id=?",
       (v_code, b.get("module"), b.get("recordId")))
    return {"status": "success"}


# ------------------------------------------------------------------ startup
@app.on_event("startup")
def startup() -> None:
    db.init_db()
    if not q1("SELECT 1 FROM release_notes LIMIT 1"):
        ex("INSERT INTO release_notes(version,title,notes,date) VALUES(?,?,?,?)",
           ("1.7.0", "First self-hosted release",
            "- Your own backend\n- Telegram payment flow\n- Village apps served directly",
            db.today_iso()))
    print("=" * 60)
    print("LPM-Replica backend running")
    print("  apiKey     :", config.API_KEY)
    print("  admin key  :", config.ADMIN_KEY, " -> open /admin/")
    print("  HMAC secret:", config.HMAC_SECRET)
    print("  UPI        :", get_setting("upi_id", config.UPI_ID))
    print("=" * 60)
