# FieldPilot backend (LPM replica) — public deployment

Backend for the FieldPilot app: registration/login, village sync, admin cockpit,
payment portal, and the /exec client contract.

## Deploy (Render free tier)

1. Push this folder to a GitHub repo.
2. Render -> New Web Service -> connect the repo.
3. Settings:
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: read from Procfile (`python -m uvicorn main:app --host 0.0.0.0 --port $PORT`)
   - Env vars: `LPM_ALLOW_UNSIGNED=0` (production: enforce HMAC-signed requests)
4. Deploy. Your URL is `https://<service>.onrender.com` — the APK endpoint becomes
   `https://<service>.onrender.com/exec` (rebuild the APK with
   `python _rebuild/patch_client.py --apply --endpoint https://<service>.onrender.com/exec`).

## Notes

- SQLite (`data/lpm.db`) ships with the pilot data (village V001 + farmer records).
  Free-tier restarts/redeploys reset files, so re-push data or upgrade to keep state.
- Admin console: `https://<service>.onrender.com/admin/` (key: LPM-ADMIN-CHANGE-ME-2026 —
  change it in config.py before going live).
