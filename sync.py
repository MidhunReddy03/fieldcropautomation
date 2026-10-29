r"""globalSyncBatch — transactional merge engine for the native offline journal.

Contract (see docs/BACKEND_CONTRACT.md):
- accept ops idempotently (replayed opIds ack without re-apply; contents must not differ)
- optimistic concurrency on (v_code, module, recordId): baseVersion must equal stored version
- conflict reply format must keep the client parse: `VERSION_CONFLICT: ... actualVersion=N`
  (client regex: actual(?:Version)?[=: ]+(\d+))
- response requires syncProtocolVersion>=3 and acceptedOperationVersions for every accepted op
- supports all module queues: farmerQueries, tasks, farmerDetails (+ any future module)
"""
import json
from typing import Any, Dict, List, Tuple

import config
import security
from db import connect, ex, get_user, now_iso, q, q1

MODULES_DEFAULT = ["farmerQueries", "tasks", "farmerDetails"]

_ID_FALLBACKS = ["recordId", "entityKey", "serverId", "clientId", "entryId",
                 "queryId", "profileId", "noteId", "lpm", "id", "localId"]


def _op_record_id(op: dict) -> str:
    for k in _ID_FALLBACKS:
        v = op.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""


def _op_fields(op: dict) -> dict:
    cf = op.get("changedFields")
    if isinstance(cf, dict):
        return cf
    cf = op.get("fields")
    if isinstance(cf, dict):
        return cf
    field = op.get("field")
    if isinstance(field, str) and field:
        return {field: op.get("value")}
    for alt in ("payload", "data"):
        cf = op.get(alt)
        if isinstance(cf, dict):
            return cf
    return {}


def _op_type(op: dict) -> str:
    t = str(op.get("operation") or op.get("type") or "UPDATE")
    return t.upper()


def _op_base_version(op: dict) -> int:
    b = op.get("baseVersion")
    try:
        v = int(str(b).strip())
        if 0 <= v < 100_000_000_000:
            return v
    except Exception:
        pass
    return -1


def _msg(conflict: bool, op_id: str, text: str) -> str:
    prefix = "VERSION_CONFLICT: " if conflict else "ERROR: "
    return prefix + text


def handle_global_sync(fields: Dict[str, Any], base_url: str) -> dict:
    v_code = str(fields.get("vCode") or "").strip()
    if not v_code:
        return {"status": "fail", "message": "vCode missing"}

    # --- auth: token required, must match an allotted village ---
    session = security.valid_access_token(str(fields.get("token") or ""))
    if not session:
        return {"status": "unauthorized", "message": "Login again",
                "syncProtocolVersion": config.SYNC_PROTOCOL_VERSION}
    user = get_user(session["username"])
    if not user:
        return {"status": "unauthorized", "message": "Account missing"}
    if session["device_id"] and str(fields.get("deviceId") or "") and \
            session["device_id"] != str(fields.get("deviceId") or ""):
        return {"status": "device_mismatch", "message": "Device mismatch"}

    allotted = q1("SELECT 1 FROM user_villages WHERE username=? AND v_code=?",
                  (session["username"], v_code))
    if not allotted:
        return {"status": "forbidden",
                "message": "Village not allotted to this account",
                "syncProtocolVersion": config.SYNC_PROTOCOL_VERSION}

    payload_raw = fields.get("queuePayload")
    if isinstance(payload_raw, str):
        try:
            payload = json.loads(payload_raw) if payload_raw.strip() else {}
        except Exception:
            return {"status": "fail", "message": "queuePayload is not valid JSON",
                    "syncProtocolVersion": config.SYNC_PROTOCOL_VERSION}
    elif isinstance(payload_raw, dict):
        payload = payload_raw
    else:
        payload = {}

    declared = int(payload.get("schemaVersion") or 0)
    if declared and declared < config.SYNC_PROTOCOL_VERSION:
        return {"status": "fail", "message": "Protocol too old; update the app",
                "syncProtocolVersion": config.SYNC_PROTOCOL_VERSION}

    modules: Dict[str, List[dict]] = {}
    raw_modules = payload.get("modules")
    if isinstance(raw_modules, dict):
        for name, queue in raw_modules.items():
            if isinstance(queue, list):
                modules[str(name)] = [m for m in queue if isinstance(m, dict)]
            elif isinstance(queue, dict):
                modules[str(name)] = [queue]
    pending_total = int(payload.get("pendingTotal") or fields.get("pendingTotal") or 0)

    accepted_ids: List[str] = []
    accepted_versions: Dict[str, int] = {}
    errors: Dict[str, str] = {}
    accepted_modules: List[str] = []
    accepted_counts: Dict[str, int] = {}

    for module, ops in modules.items():
        ok_count = 0
        any_failed = False
        for op in ops:
            op_id = str(op.get("operationId") or op.get("idempotencyKey") or "").strip()
            record_id = _op_record_id(op)
            mutation = _op_type(op)
            if not op_id:
                errors["op_missing_id_" + str(len(errors))] = _msg(False, "", "operationId missing")
                any_failed = True
                continue
            if not record_id:
                errors[op_id] = _msg(False, op_id, "recordId missing")
                any_failed = True
                continue
            fields_json = json.dumps(_op_fields(op), ensure_ascii=False)
            if len(json.dumps(op)) > config.MAX_SYNC_OP_PAYLOAD:
                errors[op_id] = _msg(False, op_id, "operation payload too large")
                any_failed = True
                continue
            base_ver = _op_base_version(op)

            # idempotency: previously applied op with identical content
            prev = q1("SELECT * FROM sync_ops WHERE op_id=?", (op_id,))
            if prev:
                if prev["v_code"] != v_code or prev["module"] != module or \
                        prev["record_id"] != record_id:
                    errors[op_id] = ("IDEMPOTENCY_CONFLICT: operation " + op_id +
                                     " has different content")
                else:
                    row = q1("SELECT version FROM sync_state WHERE v_code=? AND module=? "
                             "AND record_id=?", (v_code, module, record_id))
                    accepted_ids.append(op_id)
                    accepted_versions[op_id] = int(row["version"]) if row else 0
                    ok_count += 1
                continue

            row = q1("SELECT * FROM sync_state WHERE v_code=? AND module=? AND record_id=?",
                     (v_code, module, record_id))
            current_version = int(row["version"]) if row else 0

            if mutation == "CREATE" and row is not None:
                errors[op_id] = _msg(True, op_id,
                                     f"record {module}/{record_id} already exists; "
                                     f"actualVersion={current_version}")
                any_failed = True
                continue
            if mutation in ("UPDATE", "DELETE"):
                if row is None:
                    errors[op_id] = _msg(True, op_id,
                                         f"record {module}/{record_id} does not exist; "
                                         f"actualVersion=0")
                    any_failed = True
                    continue
                if base_ver >= 0 and base_ver != current_version:
                    errors[op_id] = _msg(True, op_id,
                                         f"record {module}/{record_id} baseVersion={base_ver} "
                                         f"actualVersion={current_version}; rebase and retry")
                    any_failed = True
                    continue

            # apply
            if mutation == "DELETE":
                ex("DELETE FROM sync_state WHERE v_code=? AND module=? AND record_id=?",
                   (v_code, module, record_id))
                new_version = current_version + 1
            else:
                if row is None:
                    ex("INSERT INTO sync_state(v_code,module,record_id,payload_json,version,"
                       "updated_by,updated_at) VALUES(?,?,?,?,1,?,?)",
                       (v_code, module, record_id, fields_json,
                        session["username"], now_iso()))
                    new_version = 1
                else:
                    merged = _deep_merge(json.loads(row["payload_json"] or "{}"), _op_fields(op))
                    ex("UPDATE sync_state SET payload_json=?, version=version+1, "
                       "updated_by=?, updated_at=? WHERE v_code=? AND module=? AND record_id=?",
                       (json.dumps(merged, ensure_ascii=False), session["username"],
                        now_iso(), v_code, module, record_id))
                    new_version = current_version + 1
            ex("INSERT INTO sync_ops(op_id,v_code,module,record_id,operation,username,device_id,"
               "applied_at) VALUES(?,?,?,?,?,?,?,?)",
               (op_id, v_code, module, record_id, mutation, session["username"],
                session["device_id"], now_iso()))
            accepted_ids.append(op_id)
            accepted_versions[op_id] = new_version
            ok_count += 1

        if ok_count > 0 and not any_failed:
            accepted_modules.append(module)
        elif ok_count > 0:
            accepted_modules.append(module)
        if ok_count > 0:
            accepted_counts[module] = ok_count

    failed_any = len(errors) > 0
    accepted_any = len(accepted_ids) > 0
    status = "success" if accepted_any and not failed_any else (
        "partial" if accepted_any else "fail")
    remaining = max(0, pending_total - len(accepted_ids))
    message = ("Sync completed" if status == "success" else
               ("Partially synced; conflicts rebased" if status == "partial" else
                "Nothing accepted; see errors"))
    return {
        "status": status,
        "acceptedModules": accepted_modules,
        "acceptedCounts": accepted_counts,
        "acceptedOperationIds": accepted_ids,
        "acceptedOperationVersions": accepted_versions,
        "failedOperationErrors": errors,
        "syncProtocolVersion": config.SYNC_PROTOCOL_VERSION,
        "remainingTotal": remaining,
        "message": message,
    }


def _deep_merge(base: dict, patch: dict) -> dict:
    out = dict(base or {})
    for k, v in (patch or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out
