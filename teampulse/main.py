"""TeamPulse API: dashboard auth, employee management, agent ingest, reports."""
import calendar
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Literal

from bson import ObjectId
from bson.errors import InvalidId
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from pymongo import UpdateOne
from pymongo.errors import DuplicateKeyError

from . import core

DOCS = bool(os.environ.get("ENABLE_DOCS"))
app = FastAPI(
    title="TeamPulse API",
    docs_url="/api/docs" if DOCS else None,
    redoc_url=None,
    openapi_url="/api/openapi.json" if DOCS else None,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in os.environ.get("CORS_ORIGINS", "*").split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer(auto_error=False)


# ---- schemas -------------------------------------------------------------------

class LoginIn(BaseModel):
    email: str = Field(max_length=200)
    password: str = Field(max_length=200)


class EmployeeIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field("", max_length=200)
    team: str = Field("", max_length=60)


class UserIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=3, max_length=200)
    password: str = Field(min_length=8, max_length=200)
    role: Literal["admin", "lead"]
    team: str = Field("", max_length=60)


class EnrollIn(BaseModel):
    code: str = Field(min_length=4, max_length=32)
    device: str = Field("", max_length=80)


class EventIn(BaseModel):
    s: int
    e: int
    st: Literal["a", "i", "l"]      # active, idle, locked
    app: str = Field("", max_length=120)
    t: str = Field("", max_length=300)


class EventsIn(BaseModel):
    events: list[EventIn] = Field(max_length=1000)


# ---- auth helpers --------------------------------------------------------------

def oid(value: str) -> ObjectId:
    try:
        return ObjectId(value)
    except (InvalidId, TypeError):
        raise HTTPException(404, "Not found")


def current_user(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    user_id = core.read_jwt(creds.credentials) if creds else None
    user = core.get_db().users.find_one({"_id": oid(user_id)}) if user_id else None
    if not user:
        raise HTTPException(401, "Sign in required")
    return user


def admin_only(user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def current_device(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> dict:
    emp = None
    if creds:
        emp = core.get_db().employees.find_one({"token_hash": core.sha256(creds.credentials)})
    if not emp:
        raise HTTPException(401, "Device not recognised")
    return emp


def scope(user: dict) -> dict:
    """Mongo filter limiting which employees a dashboard user may see."""
    return {} if user["role"] == "admin" else {"team": user.get("team", "") or "\0none"}


def public_user(user: dict) -> dict:
    return {"id": str(user["_id"]), "name": user["name"], "email": user["email"],
            "role": user["role"], "team": user.get("team", "")}


def status_of(emp: dict, now: float) -> str:
    if "token_hash" not in emp:
        return "pending"
    if now - emp.get("last_seen", 0) > core.ONLINE_WINDOW:
        return "offline"
    return {"a": "active", "i": "idle", "l": "locked"}.get((emp.get("cur") or {}).get("st"), "offline")


def range_start(date: str, tz: int) -> int:
    """Epoch seconds of local midnight; tz is minutes east of UTC."""
    try:
        day = datetime.strptime(date, "%Y-%m-%d")
    except ValueError:
        raise HTTPException(422, "Invalid date")
    return calendar.timegm(day.timetuple()) - tz * 60


DateQ = Query(..., pattern=r"^\d{4}-\d{2}-\d{2}$")
TzQ = Query(0, ge=-840, le=840)


# ---- routes: public ------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"ok": True}


@app.post("/api/auth/login")
def login(body: LoginIn):
    db, now = core.get_db(), time.time()
    user = db.users.find_one({"email": body.email.strip().lower()})
    if user and user.get("lock_until", 0) > now:
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    if not user or not core.verify_password(body.password, user["pw"]):
        if user:
            fails = user.get("fails", 0) + 1
            update = {"fails": 0, "lock_until": now + 300} if fails >= 5 else {"fails": fails}
            db.users.update_one({"_id": user["_id"]}, {"$set": update})
        else:
            core.burn_password_check(body.password)
        raise HTTPException(401, "Invalid email or password")
    db.users.update_one({"_id": user["_id"]}, {"$set": {"fails": 0, "lock_until": 0}})
    return {"token": core.make_jwt(user), "user": public_user(user)}


@app.get("/api/auth/me")
def me(user: dict = Depends(current_user)):
    return public_user(user)


# ---- routes: desktop agent -----------------------------------------------------

@app.post("/api/agent/enroll")
def enroll(body: EnrollIn):
    db, now = core.get_db(), int(time.time())
    code_hash = core.sha256(core.normalize_code(body.code))
    emp = db.employees.find_one({"code_hash": code_hash, "code_exp": {"$gt": now}})
    token = secrets.token_urlsafe(32)
    claimed = emp and db.employees.update_one(
        {"_id": emp["_id"], "code_hash": code_hash},
        {"$set": {"token_hash": core.sha256(token), "device": body.device, "enrolled": now},
         "$unset": {"code_hash": "", "code_exp": ""}},
    ).modified_count == 1
    if not claimed:
        raise HTTPException(400, "Invalid or expired activation code")
    return {"token": token, "name": emp["name"]}


@app.post("/api/agent/events")
def ingest(body: EventsIn, emp: dict = Depends(current_device)):
    db, now = core.get_db(), int(time.time())
    ops, newest = [], None
    for ev in body.events:
        if ev.e < ev.s or ev.e - ev.s > 86400 or ev.s < now - 30 * 86400 or ev.e > now + 300:
            continue
        ops.append(UpdateOne(
            {"emp": emp["_id"], "s": ev.s},
            {"$set": {"e": ev.e, "d": ev.e - ev.s, "st": ev.st, "app": ev.app, "t": ev.t},
             "$setOnInsert": {"created": datetime.now(timezone.utc)}},
            upsert=True,
        ))
        if newest is None or ev.e >= newest.e:
            newest = ev
    if ops:
        db.events.bulk_write(ops, ordered=False)
    seen = {"last_seen": now}
    if newest:
        seen["cur"] = {"st": newest.st, "app": newest.app}
    db.employees.update_one({"_id": emp["_id"]}, {"$set": seen})
    return {"accepted": len(ops)}


# ---- routes: employees ---------------------------------------------------------

@app.get("/api/employees")
def list_employees(user: dict = Depends(current_user)):
    now = time.time()
    rows = core.get_db().employees.find(scope(user))
    return sorted(({
        "id": str(e["_id"]), "name": e["name"], "email": e.get("email", ""), "team": e.get("team", ""),
        "status": status_of(e, now), "last_seen": e.get("last_seen", 0),
        "device": e.get("device", ""), "enrolled": e.get("enrolled"),
    } for e in rows), key=lambda r: r["name"].lower())


@app.post("/api/employees", status_code=201)
def create_employee(body: EmployeeIn, _: dict = Depends(admin_only)):
    code = core.new_code()
    doc = {"name": body.name.strip(), "email": body.email.strip(), "team": body.team.strip(),
           "code_hash": core.sha256(core.normalize_code(code)),
           "code_exp": int(time.time()) + core.CODE_TTL, "created": int(time.time()), "last_seen": 0}
    res = core.get_db().employees.insert_one(doc)
    return {"id": str(res.inserted_id), "code": code}


@app.post("/api/employees/{emp_id}/code")
def reissue_code(emp_id: str, _: dict = Depends(admin_only)):
    """New activation code. Also disconnects the currently enrolled device."""
    code = core.new_code()
    res = core.get_db().employees.update_one(
        {"_id": oid(emp_id)},
        {"$set": {"code_hash": core.sha256(core.normalize_code(code)),
                  "code_exp": int(time.time()) + core.CODE_TTL},
         "$unset": {"token_hash": "", "device": "", "enrolled": "", "cur": ""}},
    )
    if not res.matched_count:
        raise HTTPException(404, "Employee not found")
    return {"code": code}


@app.delete("/api/employees/{emp_id}", status_code=204)
def delete_employee(emp_id: str, _: dict = Depends(admin_only)):
    db, key = core.get_db(), oid(emp_id)
    if not db.employees.delete_one({"_id": key}).deleted_count:
        raise HTTPException(404, "Employee not found")
    db.events.delete_many({"emp": key})


# ---- routes: reports -----------------------------------------------------------

@app.get("/api/overview")
def overview(date: str = DateQ, days: int = Query(1, ge=1, le=31), tz: int = TzQ,
             user: dict = Depends(current_user)):
    db, now = core.get_db(), time.time()
    start = range_start(date, tz)
    end = start + days * 86400
    emps = list(db.employees.find(scope(user)))
    totals = {}
    if emps:
        match = {"emp": {"$in": [e["_id"] for e in emps]}, "s": {"$gte": start, "$lt": end}}
        for r in db.events.aggregate([
            {"$match": match},
            {"$group": {"_id": {"emp": "$emp", "st": "$st"}, "d": {"$sum": "$d"},
                        "first": {"$min": "$s"}, "last": {"$max": "$e"}}},
        ]):
            t = totals.setdefault(r["_id"]["emp"], {"a": 0, "i": 0, "l": 0, "first": None, "last": None, "apps": {}})
            t[r["_id"]["st"]] = r["d"]
            t["first"] = r["first"] if t["first"] is None else min(t["first"], r["first"])
            t["last"] = r["last"] if t["last"] is None else max(t["last"], r["last"])
        for r in db.events.aggregate([
            {"$match": {**match, "st": "a", "app": {"$ne": ""}}},
            {"$group": {"_id": {"emp": "$emp", "app": "$app"}, "d": {"$sum": "$d"}}},
        ]):
            totals.setdefault(r["_id"]["emp"], {"a": 0, "i": 0, "l": 0, "first": None, "last": None, "apps": {}}
                              )["apps"][r["_id"]["app"]] = r["d"]
    rows = []
    for e in emps:
        t = totals.get(e["_id"], {"a": 0, "i": 0, "l": 0, "first": None, "last": None, "apps": {}})
        rows.append({
            "id": str(e["_id"]), "name": e["name"], "email": e.get("email", ""), "team": e.get("team", ""),
            "status": status_of(e, now), "last_seen": e.get("last_seen", 0),
            "active": t["a"], "idle": t["i"], "locked": t["l"], "first": t["first"], "last": t["last"],
            "top_app": max(t["apps"], key=t["apps"].get) if t["apps"] else "",
        })
    rows.sort(key=lambda r: r["name"].lower())
    return {"start": start, "end": end, "employees": rows}


@app.get("/api/employees/{emp_id}/day")
def employee_day(emp_id: str, date: str = DateQ, tz: int = TzQ, user: dict = Depends(current_user)):
    db, now = core.get_db(), time.time()
    emp = db.employees.find_one({"_id": oid(emp_id), **scope(user)})
    if not emp:
        raise HTTPException(404, "Employee not found")
    start = range_start(date, tz)
    end = start + 86400
    events = list(db.events.find({"emp": emp["_id"], "s": {"$gte": start, "$lt": end}},
                                 {"_id": 0, "s": 1, "e": 1, "st": 1, "app": 1, "t": 1}).sort("s", 1).limit(5000))
    totals, apps = {"a": 0, "i": 0, "l": 0}, {}
    for ev in events:
        d = ev["e"] - ev["s"]
        totals[ev["st"]] += d
        if ev["st"] == "a" and ev["app"]:
            apps[ev["app"]] = apps.get(ev["app"], 0) + d
    return {
        "employee": {"id": str(emp["_id"]), "name": emp["name"], "team": emp.get("team", ""),
                     "email": emp.get("email", ""), "status": status_of(emp, now),
                     "last_seen": emp.get("last_seen", 0), "device": emp.get("device", "")},
        "start": start, "end": end,
        "active": totals["a"], "idle": totals["i"], "locked": totals["l"],
        "apps": sorted(({"app": k, "seconds": v} for k, v in apps.items()), key=lambda x: -x["seconds"])[:15],
        "events": events,
    }


# ---- routes: dashboard users ---------------------------------------------------

@app.get("/api/users")
def list_users(_: dict = Depends(admin_only)):
    return sorted((public_user(u) for u in core.get_db().users.find()), key=lambda u: u["name"].lower())


@app.post("/api/users", status_code=201)
def create_user(body: UserIn, _: dict = Depends(admin_only)):
    team = body.team.strip()
    if body.role == "lead" and not team:
        raise HTTPException(422, "A team lead needs a team name")
    doc = {"name": body.name.strip(), "email": body.email.strip().lower(), "pw": core.hash_password(body.password),
           "role": body.role, "team": team if body.role == "lead" else "", "created": int(time.time())}
    try:
        res = core.get_db().users.insert_one(doc)
    except DuplicateKeyError:
        raise HTTPException(409, "A user with this email already exists")
    return {"id": str(res.inserted_id)}


@app.delete("/api/users/{user_id}", status_code=204)
def delete_user(user_id: str, admin: dict = Depends(admin_only)):
    if oid(user_id) == admin["_id"]:
        raise HTTPException(400, "You cannot delete your own account")
    if not core.get_db().users.delete_one({"_id": oid(user_id)}).deleted_count:
        raise HTTPException(404, "User not found")
