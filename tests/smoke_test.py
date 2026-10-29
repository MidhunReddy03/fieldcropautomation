"""End-to-end smoke test — signs requests exactly like the patched client will.

Run:  python tests/smoke_test.py   (server must be on 127.0.0.1:8000)
"""
import hashlib
import hmac
import json
import sys
import urllib.request
import urllib.error
import datetime

sys.path.insert(0, ".")
import config  # noqa: E402

BASE = "http://127.0.0.1:8000"
PASS = 0
FAIL = 0
RUN = hashlib.sha256(str(datetime.datetime.now()).encode()).hexdigest()[:6]


def sign(fields: dict) -> str:
    body_map = {"action": fields["action"]}
    for k, v in fields.items():
        if k not in ("action", "signature", "tamperFlags", "clientHmacCheck"):
            body_map[k] = v
    chc = hmac.new(config.HMAC_SECRET.encode(), config.CLIENT_HMAC_MESSAGE.encode(),
                   hashlib.sha256).hexdigest()
    body_map["clientHmacCheck"] = chc
    body_map["tamperFlags"] = {"signatureMismatch": False, "isRooted": False,
                               "isEmulator": False, "isDebug": False}
    canonical = json.dumps(body_map)
    sig = hmac.new(config.HMAC_SECRET.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    return canonical[:-1] + ',"signature":"' + sig + '"}'


def call(action: str, **fields) -> dict:
    fields["action"] = action
    fields.setdefault("apiKey", config.API_KEY)
    fields.setdefault("deviceId", "test-device-001")
    body = sign(fields)
    req = urllib.request.Request(BASE + "/exec", data=body.encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


def check(name: str, cond: bool, extra: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("PASS", name)
    else:
        FAIL += 1
        print("FAIL", name, extra)


def admin(method: str, path: str, body=None):
    req = urllib.request.Request(BASE + "/admin/api" + path,
                                 data=json.dumps(body).encode() if body else None,
                                 method=method if body else "GET",
                                 headers={"X-Admin-Key": config.ADMIN_KEY,
                                          "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())


# ------------------------------------------------------------- content (no auth)
j = call("checkUpdate")
# banner-off contract: code must NOT exceed the client's own version (42),
# and no apkUrl should be pushed by default
check("checkUpdate", j.get("latestVersionCode", 99) <= 42 and not (j.get("apkUrl") or "").strip(),
      json.dumps(j))
j = call("getSupportInfo")
check("getSupportInfo", j.get("status") == "success" and "how_to_use" in j)
j = call("getVideosCatalog")
check("getVideosCatalog", j.get("status") == "success" and "videos" in j)
j = call("getReleaseNotes")
check("getReleaseNotes", j.get("status") == "success" and j.get("version"))

# ------------------------------------------------------------- register + login
USER = "smokeuser_" + hashlib.sha256(str(hash("x")).encode()).hexdigest()[:8]
jsp = call("registerUser", username=USER, subscriberName="Smoke Tester", email="a@b.c",
           phoneNumber="9000000000", district="D", mandal="M", village="Vgv",
           referralUsername="adminprem")
check("registerUser.grants trial", jsp.get("status") == "registered" and jsp.get("trialGranted") is True,
      json.dumps(jsp))
TP = jsp["tempPassword"]

jbad = call("login", username=USER, password="wrong-password-99")
check("login wrong pw unauthorized", jbad.get("status") == "unauthorized", json.dumps(jbad))

j = call("login", username=USER, password=TP)
check("login success", j.get("status") == "success", json.dumps(j))
check("login mustChange", j.get("mustChange") is True)
check("login trial_active", j.get("accountState") == "trial_active", json.dumps(j))
TOKEN, REFRESH = j["token"], j["refreshToken"]

j = call("changePassword", token=TOKEN, newPassword="NewStrongPw1!")
check("changePassword", j.get("status") == "updated", json.dumps(j))
j = call("login", username=USER, password="NewStrongPw1!")
check("relogin ok", j.get("status") == "success" and j.get("mustChange") is False)
TOKEN = j["token"]
REFRESH = j["refreshToken"]   # keep the pair together, exactly like the client does

j = call("refreshToken", token=TOKEN, refreshToken=REFRESH)
check("refreshToken rotates", j.get("status") == "success" and j.get("token") != TOKEN,
      json.dumps(j))
TOKEN, REFRESH = j["token"], j["refreshToken"]
check("refresh tracks expiry", "subscriptionExpiryDate" in j)

# ------------------------------------------------------------- villages flow
j = call("getVillages", token=TOKEN)
check("getVillages empty at first", j.get("status") == "success" and j.get("villages") == [])

adm = admin("POST", "/villages/save", {"v_code": "V001", "name": "Kondapalli", "slug": "v001"})
check("admin creates village", adm.get("status") == "ok", json.dumps(adm))
adm = admin("POST", "/user/allot_village", {"username": USER, "v_code": "V001"})
check("admin allots village", adm.get("status") == "ok")
j = call("getVillages", token=TOKEN)
check("getVillages returns allotment", len(j.get("villages") or []) == 1 and
      j["villages"][0]["vCode"] == "V001" and "/app/v001/" in j["villages"][0]["url"],
      json.dumps(j))

# ------------------------------------------------------------- subscription flow
j = call("getSubscriptionOffers", username=USER)
check("offers list", j.get("status") == "success" and len(j.get("offers") or []) >= 1 and
      {"planName", "upfrontAmount", "planId", "linkUrl", "buttonOrder", "enabled"}
      <= set(j["offers"][0].keys()), json.dumps(j))
plan = j["offers"][0]

j = call("createWebPortalSession", username=USER, planId=plan["planId"], planName=plan["planName"])
check("portal session", j.get("status") == "success" and "/portal/" in j.get("portalUrl", ""),
      json.dumps(j))
portal_url = j["portalUrl"]
ps_token = portal_url.rsplit("/", 1)[-1]

sess = json.loads(urllib.request.urlopen(BASE + "/portal/api/session/" + ps_token).read())
check("portal session page data", sess.get("plan", {}).get("plan_id") == plan["planId"] and
      "upi://pay" in sess.get("upiIntent", ""), json.dumps(sess)[:200])
qr = urllib.request.urlopen(BASE + "/portal/api/qr/" + ps_token).read()
check("portal QR rendered", qr.startswith(b"<"), "not svg")

claim = json.loads(urllib.request.urlopen(urllib.request.Request(
    BASE + "/portal/api/claim", data=json.dumps(
        {"token": ps_token, "utr": "UTR12345", "note": "paid on phone"}).encode(),
    headers={"Content-Type": "application/json"})).read())
check("portal claim pending", claim.get("status") == "pending", json.dumps(claim))

pay_list = admin("GET", "/payments?status=pending").get("payments", [])
check("admin sees pending payment", any(p["username"] == USER for p in pay_list))
prow = [p for p in pay_list if p["username"] == USER][-1]
adm = admin("POST", "/payments/approve", {"id": prow["id"]})
check("admin approves payment", adm.get("username") == USER and adm.get("amount") == plan["upfrontAmount"],
      json.dumps(adm))

j = call("getSubscriptionStatus", username=USER)
check("status active after approve", j.get("accountState") == "active" and
      j.get("subscriptionExpiryDate", "") > "2025", json.dumps(j))

# ------------------------------------------------------------- access control
adm = admin("POST", "/user/set_access", {"username": USER, "access": False})
j = call("getSubscriptionStatus", username=USER)
check("admin revoke flips wall", j.get("accountState") == "subscription_required", json.dumps(j))
adm = admin("POST", "/user/set_access", {"username": USER, "access": True})
j = call("getSubscriptionStatus", username=USER)
check("admin grant restores", j.get("accountState") == "active")
adm = admin("POST", "/user/set_blocked", {"username": USER, "blocked": True})
j = call("login", username=USER, password="NewStrongPw1!")
check("blocked login rejected", j.get("status") == "blocked", json.dumps(j))
admin("POST", "/user/set_blocked", {"username": USER, "blocked": False})

# ------------------------------------------------------------- block bad device
j2 = call("login", username=USER, password="NewStrongPw1!", deviceId="other-device-777")
check("device_mismatch enforced", j2.get("status") == "device_mismatch", json.dumps(j2))
admin("POST", "/user/unbind_device", {"username": USER})
j2 = call("login", username=USER, password="NewStrongPw1!", deviceId="other-device-777")
check("rebind after unbind", j2.get("status") == "success")
TOKEN2 = j2["token"]

# ------------------------------------------------------------- sync engine
opsv = 0
def sync_call(token, device, v_code, modules):
    body = {
        "action": "getSyncProbe",  # overwritten below
    }
    # NOTE: real signature path
    fields = {"apiKey": config.API_KEY, "deviceId": device, "token": token,
              "vCode": v_code, "capturedAt": "2026-10-28T09:00:00Z",
              "pendingTotal": "3", "queuePayload": json.dumps({
                  "schemaVersion": 3, "source": "room_operation_journal",
                  "pendingTotal": 3,
                  "modules": modules,
                  "failedTotal": 0, "failedModules": {},
                  "conflictTotal": 0, "conflictModules": {}})}
    return call("globalSyncBatch", **fields)


r1 = sync_call(TOKEN2, "other-device-777", "V001", {"farmerDetails": [{
    "operationId": "op-create-1-" + RUN, "recordId": "farmer-" + RUN,
    "operation": "CREATE",
    "changedFields": {"lpm": "77", "ownerName": "Ravi", "aadhaar": "456789123456",
                       "mobile": "9000000000", "crop": "Paddy"},
    "idempotencyKey": "op-create-1-" + RUN, "baseVersion": 0}]})
check("sync CREATE accepted", r1.get("status") == "success" and
      r1["acceptedOperationIds"] == ["op-create-1-" + RUN] and
      r1["acceptedOperationVersions"].get("op-create-1-" + RUN) == 1 and
      r1.get("syncProtocolVersion") == 3, json.dumps(r1))

REC = "farmer-" + RUN
r2 = sync_call(TOKEN2, "other-device-777", "V001", {"farmerDetails": [{
    "operationId": "op-update-1-" + RUN, "recordId": REC, "operation": "UPDATE",
    "changedFields": {"crop": "MTU-7029"}, "baseVersion": 1}]})
check("sync UPDATE accepted v2", r2["acceptedOperationVersions"].get("op-update-1-" + RUN) == 2,
      json.dumps(r2))

r3 = sync_call(TOKEN2, "other-device-777", "V001", {"farmerDetails": [{
    "operationId": "op-update-2-" + RUN, "recordId": REC, "operation": "UPDATE",
    "changedFields": {"crop": "WRONG"}, "baseVersion": 1}]})
msg = "".join(r3.get("failedOperationErrors", {}).values())
check("sync conflict format", r3["acceptedOperationIds"] == [] and
      "VERSION_CONFLICT" in msg and "actualVersion=2" in msg, msg)

r4 = sync_call(TOKEN2, "other-device-777", "V001", {"farmerDetails": [{
    "operationId": "op-create-1-" + RUN, "recordId": REC, "operation": "CREATE",
    "changedFields": {"lpm": "77", "ownerName": "Ravi"}, "baseVersion": 0}]})
check("sync idempotent replay", r4.get("status") == "success" and
      r4["acceptedOperationIds"] == ["op-create-1-" + RUN] and
      r4["acceptedOperationVersions"].get("op-create-1-" + RUN, 0) >= 1, json.dumps(r4))

req_v = urllib.request.Request(BASE + "/api/village/V001",
                               headers={"X-Village-Token": config.ADMIN_KEY})
recs = json.loads(urllib.request.urlopen(req_v).read())
check("village REST sees merged record",
      recs["modules"]["farmerDetails"][REC]["fields"]["crop"] == "MTU-7029",
      json.dumps(recs))

# page lookup
lk = json.loads(urllib.request.urlopen(BASE + "/api/village/lookup/v001").read())
check("village lookup", lk.get("vCode") == "V001" and lk.get("name") == "Kondapalli")

# feedback
j = call("submitFeedback", token=TOKEN2, feedback="Great app", rating=5,
         appVersion="1.7.0", device="Pixel")
check("submitFeedback", j.get("status") == "updated", json.dumps(j))

# rejection of a CORRUPTED signature (works in both dev and prod modes)
fields = {"action": "getSupportInfo", "apiKey": config.API_KEY, "deviceId": "t"}
good = sign(fields)
BAD_SIG = "0" * 64
bad = good[:-66] + BAD_SIG + '"}'   # replace the 64-char hex signature with zeros
req = urllib.request.Request(BASE + "/exec", data=bad.encode(),
                             headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    j = json.loads(r.read())
check("wrong signature rejected", j.get("status") == "invalid_signature", json.dumps(j))

# unsigned requests: accepted only in dev mode (LPM_ALLOW_UNSIGNED=1)
req = urllib.request.Request(BASE + "/exec", data=json.dumps(
    {"action": "getSupportInfo", "apiKey": config.API_KEY, "deviceId": "t"}).encode(),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req) as r:
    j = json.loads(r.read())
if config.ALLOW_UNSIGNED_DEFAULT:
    check("unsigned accepted in dev mode", j.get("status") == "success", json.dumps(j))
else:
    check("unsigned rejected in prod mode", j.get("status") == "invalid_signature", json.dumps(j))

print(f"\n===== {PASS} passed, {FAIL} failed =====")
sys.exit(1 if FAIL else 0)
