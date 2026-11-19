"""Shared configuration and the SQLite state plane.

Three processes (web console / resolver / authoritative endpoint) share one
SQLite database in WAL mode:

  control    -- desired behaviour of the authoritative endpoint, written by
                the web console, read by the authoritative endpoint on every
                query.  Every edit bumps an integer *version*; the resolver
                only accepts an SRV set and its glue/A records when every
                record carries the same version TXT (see auth_server).
  srv_cache  -- the resolver's atomic SRV group cache.  A row is written only
                when a complete, same-version result has been assembled.  The
                group lifetime is the minimum expiry of its records, stored as
                an absolute epoch so a restart cannot extend anything.
  a_cache    -- the plain service.example A cache (independent of the SRV
                group; the original A query path keeps working as before).
  query_log  -- every client query the resolver answered, with its source.
  auth_log   -- every query the authoritative endpoint saw, with the action.
"""
from __future__ import annotations

import json
import os
import sqlite3
import time

# --------------------------------------------------------------------------
# Configuration (environment overridable; defaults are the spec values).
# --------------------------------------------------------------------------
FIXED_DOMAIN = os.environ.get("FIXED_DOMAIN", "service.example").strip().rstrip(".")
FQDN = FIXED_DOMAIN + "."
SRV_OWNER = os.environ.get("SRV_OWNER", f"_ldap._tcp.{FIXED_DOMAIN}").rstrip(".")
SRV_NAME = SRV_OWNER + "."
VERSION_LABEL = os.environ.get("VERSION_LABEL", f"_cfgver.{FIXED_DOMAIN}").rstrip(".")
VERSION_NAME = VERSION_LABEL + "."

TARGET1 = os.environ.get("TARGET1_NAME", f"ldap1.{FIXED_DOMAIN}").rstrip(".") + "."
TARGET2 = os.environ.get("TARGET2_NAME", f"ldap2.{FIXED_DOMAIN}").rstrip(".") + "."

DB_PATH = os.environ.get("DB_PATH", "/data/app.db")

# One shared budget for the whole resolution round: from the first upstream
# SRV query, every supplementary A lookup *and every retry* draws from these
# same 2 seconds.
FETCH_BUDGET = float(os.environ.get("FETCH_BUDGET", os.environ.get("UPSTREAM_TIMEOUT", "2.0")))

# Authoritative-side record TTLs.  They deliberately differ so the group's
# min-expiry rule is observable: SRV 10s vs glue A 5s -> the group lives 5s.
SRV_TTL = int(os.environ.get("SRV_TTL", "10"))
GLUE_TTL = int(os.environ.get("GLUE_TTL", "5"))
A_TTL = int(os.environ.get("A_TTL", "5"))

AUTH_HOST = os.environ.get("AUTH_HOST", "127.0.0.1")
AUTH_PORT = int(os.environ.get("AUTH_PORT", "5354"))
RESOLVER_HOST = os.environ.get("RESOLVER_HOST", "127.0.0.1")
RESOLVER_PORT = int(os.environ.get("RESOLVER_PORT", "5353"))
WEB_PORT = int(os.environ.get("WEB_PORT", "8000"))

DEFAULT_IP1 = os.environ.get("DEFAULT_IP1", "192.0.2.11")
DEFAULT_IP2 = os.environ.get("DEFAULT_IP2", "192.0.2.12")
DEFAULT_APEX_IP = os.environ.get("DEFAULT_APEX_IP", "192.0.2.10")
DEFAULT_PORT1 = int(os.environ.get("DEFAULT_PORT1", "389"))
DEFAULT_PORT2 = int(os.environ.get("DEFAULT_PORT2", "3890"))
DEFAULT_DELAY = float(os.environ.get("DEFAULT_DELAY", "3.0"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS control (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mode TEXT NOT NULL,               -- ok | delay | drop (whole-endpoint injection)
  t2_mode TEXT NOT NULL DEFAULT 'ok',  -- target-2 A path: ok | drop | stale_version
  delay_seconds REAL NOT NULL,
  include_glue_a INTEGER NOT NULL,  -- 1: additional A in the SRV reply; 0: omit
  t1_ip TEXT NOT NULL,
  t1_port INTEGER NOT NULL,
  t2_ip TEXT NOT NULL,
  t2_port INTEGER NOT NULL,
  version INTEGER NOT NULL,         -- bumped on every edit; atomicity token
  updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS srv_cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL,         -- authoritative config version of the set
  fetched_at REAL NOT NULL,
  group_until REAL NOT NULL,        -- min(record expiries): whole-group deadline
  records TEXT NOT NULL             -- JSON: [{type, name, ttl, rdata...}]
);
CREATE TABLE IF NOT EXISTS a_cache (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  qname TEXT NOT NULL,
  ip TEXT NOT NULL,
  fetched_at REAL NOT NULL,
  fresh_until REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS query_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, source TEXT, rcode TEXT, answers TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS auth_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts REAL NOT NULL,
  qname TEXT, qtype TEXT, mode TEXT, action TEXT, detail TEXT
);
"""

_LOG_TABLES = ("query_log", "auth_log")


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def init_db() -> None:
    directory = os.path.dirname(DB_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with _connect() as c:
        c.executescript(SCHEMA)
        # Migration for databases created before the per-target injection knob.
        cols = {r[1] for r in c.execute("PRAGMA table_info(control)")}
        if "t2_mode" not in cols:
            c.execute("ALTER TABLE control ADD COLUMN t2_mode TEXT NOT NULL DEFAULT 'ok'")
        c.execute(
            "INSERT OR IGNORE INTO control(id, mode, t2_mode, delay_seconds,"
            "   include_glue_a, t1_ip, t1_port, t2_ip, t2_port, version, updated_at)"
            " VALUES (1, 'ok', 'ok', ?, 1, ?, ?, ?, ?, 1, ?)",
            (DEFAULT_DELAY, DEFAULT_IP1, DEFAULT_PORT1, DEFAULT_IP2, DEFAULT_PORT2,
             time.time()),
        )


# --------------------------------------------------------------------------
# control table (web writes, authoritative endpoint reads)
# --------------------------------------------------------------------------
def get_control() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM control WHERE id = 1").fetchone()
        return dict(row) if row else None


def set_control(fields: dict) -> dict:
    """Partial update of the control row.  Every accepted update bumps the
    configuration version atomically, which invalidates in-flight resolver
    rounds that mix records from different config generations."""
    allowed = {
        "mode", "t2_mode", "delay_seconds", "include_glue_a",
        "t1_ip", "t1_port", "t2_ip", "t2_port",
    }
    sets, vals = [], []
    for key, val in fields.items():
        if key in allowed:
            sets.append(f"{key} = ?")
            vals.append(val)
    if not sets:
        return get_control()
    sets.append("version = version + 1")
    sets.append("updated_at = ?")
    vals.append(time.time())
    with _connect() as c:
        c.execute(f"UPDATE control SET {', '.join(sets)} WHERE id = 1", vals)
    return get_control()


# --------------------------------------------------------------------------
# SRV group cache (resolver only) -- one atomic row per SRV owner name
# --------------------------------------------------------------------------
def get_srv_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM srv_cache WHERE id = 1").fetchone()
        if not row:
            return None
        out = dict(row)
        out["records"] = json.loads(out["records"])
        return out


def put_srv_cache(version: int, records: list[dict], fetched_at: float) -> dict:
    """Persist a *complete, same-version* record set.  Each record's expiry is
    fetched_at + its own TTL; the group deadline is the earliest of them."""
    group_until = min(fetched_at + int(r["ttl"]) for r in records)
    payload = json.dumps(records, sort_keys=True)
    with _connect() as c:
        c.execute(
            "INSERT INTO srv_cache(id, version, fetched_at, group_until, records)"
            " VALUES (1, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET version = excluded.version,"
            "   fetched_at = excluded.fetched_at, group_until = excluded.group_until,"
            "   records = excluded.records",
            (version, fetched_at, group_until, payload),
        )
    return get_srv_cache()


def clear_srv_cache() -> None:
    with _connect() as c:
        c.execute("DELETE FROM srv_cache WHERE id = 1")


# --------------------------------------------------------------------------
# plain A cache (service.example A path, independent of the SRV group)
# --------------------------------------------------------------------------
def get_a_cache() -> dict | None:
    with _connect() as c:
        row = c.execute("SELECT * FROM a_cache WHERE id = 1").fetchone()
        return dict(row) if row else None


def put_a_cache(ip: str, now: float) -> None:
    with _connect() as c:
        c.execute(
            "INSERT INTO a_cache(id, qname, ip, fetched_at, fresh_until)"
            " VALUES (1, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET qname = excluded.qname, ip = excluded.ip,"
            "   fetched_at = excluded.fetched_at, fresh_until = excluded.fresh_until",
            (FQDN, ip, now, now + A_TTL),
        )


# --------------------------------------------------------------------------
# logs
# --------------------------------------------------------------------------
def _log(table: str, columns: tuple[str, ...], values: tuple) -> None:
    assert table in _LOG_TABLES
    cols = ", ".join(columns)
    marks = ", ".join("?" for _ in columns)
    with _connect() as c:
        c.execute(f"INSERT INTO {table}({cols}) VALUES ({marks})", values)
        c.execute(
            f"DELETE FROM {table} WHERE id NOT IN"
            f" (SELECT id FROM {table} ORDER BY id DESC LIMIT 300)"
        )


def log_query(qname, qtype, source, rcode, answers, detail) -> None:
    _log(
        "query_log",
        ("ts", "qname", "qtype", "source", "rcode", "answers", "detail"),
        (time.time(), qname, qtype, source, rcode, answers, detail),
    )


def log_auth(qname, qtype, mode, action, detail) -> None:
    _log(
        "auth_log",
        ("ts", "qname", "qtype", "mode", "action", "detail"),
        (time.time(), qname, qtype, mode, action, detail),
    )


def recent(table: str, limit: int = 15) -> list[dict]:
    assert table in _LOG_TABLES
    with _connect() as c:
        rows = c.execute(
            f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]
