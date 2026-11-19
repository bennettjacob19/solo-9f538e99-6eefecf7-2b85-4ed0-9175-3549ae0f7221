"""Caching UDP DNS resolver for the atomic SRV-group exercise.

Resolution rules (see README for the full contract):

  * An SRV query for _ldap._tcp.<domain> must yield a *complete* result: both
    SRV RRs (primary/backup, priority, port) and one A record per target.  The
    authoritative endpoint normally includes the A records as glue in one UDP
    reply; when it omits them the resolver back-fills the missing A records
    with concurrent upstream queries.
  * One shared budget (FETCH_BUDGET, 2s) governs the whole round, starting at
    the first upstream SRV query: every supplementary lookup and every retry
    draws from those same 2 seconds.  Each attempt uses a dedicated socket and
    a random transaction ID, so late datagrams can never be mis-associated.
  * Every upstream record carries a config-version TXT.  Only records from the
    same version may be combined; a mixed-version round is discarded (and
    retried while the budget allows).  Only a complete, same-version result is
    ever answered to a client or written into the cache.
  * The cached group expires at the earliest expiry among its records.  Every
    RR answered from the cache is capped to that remaining group TTL.  Expiry
    triggers a full re-fetch of the whole group.
  * If a complete same-version result cannot be assembled within the budget,
    the answer is SERVFAIL containing neither SRV nor A records, and nothing
    is cached.
  * The plain service.example A query path is independent and keeps working.

The resolver reports the answer source in an additional TXT record
(_src.<domain> TXT "source=upstream|cache-fresh|none ..."); the internal
version TXT never leaves the resolver.
"""
from __future__ import annotations

import math
import random
import socket
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, CLASS, QTYPE, RCODE, RR, SRV, TXT, DNSHeader, DNSRecord

from . import common

# Per-attempt socket timeout.  Retries (new socket, new transaction ID) keep
# happening until the shared round deadline is reached.
ATTEMPT_TIMEOUT = float(common.FETCH_BUDGET / 2)

# Bounded pool for client packets: back-pressure under a query storm instead
# of unbounded thread creation.  Sized generously so readiness probes never
# queue behind a burst of in-flight resolution rounds.
_CLIENT_POOL = ThreadPoolExecutor(max_workers=128, thread_name_prefix="resolver")


def _same_name(a, b) -> bool:
    return str(a).rstrip(".").lower() == str(b).rstrip(".").lower()


# --------------------------------------------------------------------------
# Upstream transport: one dedicated socket per attempt, shared round deadline
# --------------------------------------------------------------------------
def upstream_query(qname: str, qtype: str, deadline: float) -> DNSRecord | None:
    """Single upstream attempt.  Returns None on timeout / unusable datagram.

    The caller passes the *shared* monotonic deadline; this function never
    waits past it.  Retrying means calling again, so every retry of the SRV
    query and of every supplementary A query is bounded by the same budget.
    """
    query = DNSRecord.question(qname, qtype)
    query.header.id = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(query.pack(), (common.AUTH_HOST, common.AUTH_PORT))
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0.02:
                return None
            sock.settimeout(min(remaining, ATTEMPT_TIMEOUT))
            try:
                data, _addr = sock.recvfrom(4096)
            except socket.timeout:
                return None
            try:
                resp = DNSRecord.parse(data)
            except Exception:
                continue  # unparsable stray datagram: keep waiting
            if resp.header.id != query.header.id:
                continue  # stray/late packet for someone else: ignore
            if not _same_name(resp.q.qname, query.q.qname) or resp.q.qtype != query.q.qtype:
                continue
            return resp
    except OSError:
        return None
    finally:
        sock.close()


def query_with_retry(qname: str, qtype: str, deadline: float) -> DNSRecord | None:
    """Keep attempting (fresh socket + random ID each time) until the shared
    round deadline is exhausted."""
    while True:
        resp = upstream_query(qname, qtype, deadline)
        if resp is not None:
            return resp
        if deadline - time.monotonic() <= 0.02:
            return None


def _extract_version(resp: DNSRecord) -> int | None:
    for rr in resp.ar:
        if rr.rtype == QTYPE.TXT:
            txt = str(rr.rdata).strip('"')
            if txt.startswith("v="):
                try:
                    return int(txt[2:].strip())
                except ValueError:
                    return None
    return None


# --------------------------------------------------------------------------
# Reply construction
# --------------------------------------------------------------------------
def _record_to_rr(rec: dict, ttl: int) -> RR:
    if rec["type"] == "SRV":
        return RR(rec["name"], QTYPE.SRV, CLASS.IN, ttl,
                  SRV(rec["priority"], rec["weight"], rec["port"], rec["target"]))
    return RR(rec["name"], QTYPE.A, CLASS.IN, ttl, A(rec["ip"]))


def _reply(query: DNSRecord, rcode: int, records=(), source="none", detail=""):
    rep = DNSRecord(
        DNSHeader(id=query.header.id, qr=1, aa=0, ra=1,
                  rd=query.header.rd, rcode=rcode),
        q=query.q,
    )
    for rec in records:
        rep.add_answer(_record_to_rr(rec, rec.get("reply_ttl", rec["ttl"])))
    meta = f"source={source}" + (f" {detail}" if detail else "")
    rep.add_ar(RR(f"_src.{common.FQDN}", QTYPE.TXT, CLASS.IN, 0, TXT(meta)))
    return rep


# --------------------------------------------------------------------------
# Atomic SRV group resolution
# --------------------------------------------------------------------------
def _fetch_srv_phase(deadline: float):
    """Phase 1: get one SRV answer (retries share the round budget).

    Returns (srv_record_dicts, version, glue_map) or None.
    """
    while deadline - time.monotonic() > 0.02:
        resp = query_with_retry(common.SRV_NAME, "SRV", deadline)
        if resp is None:
            return None
        if resp.header.rcode != RCODE.NOERROR:
            return None
        version = _extract_version(resp)
        if version is None:
            return None  # no provenance: cannot be combined with anything
        srv_rrs = sorted(
            (rr for rr in resp.rr if rr.rtype == QTYPE.SRV),
            key=lambda rr: rr.rdata.priority,
        )
        if not srv_rrs:
            return None
        glue = {}
        for rr in resp.ar:
            if rr.rtype == QTYPE.A:
                glue[str(rr.rname).rstrip(".").lower()] = (str(rr.rdata), int(rr.ttl))
        srv_records = [{
            "type": "SRV", "name": common.SRV_NAME, "ttl": int(rr.ttl),
            "priority": int(rr.rdata.priority), "weight": int(rr.rdata.weight),
            "port": int(rr.rdata.port),
            "target": str(rr.rdata.target).rstrip(".") + ".",
        } for rr in srv_rrs]
        return srv_records, version, glue


def _fetch_a_phase(targets: list[str], version: int, glue: dict, deadline: float):
    """Phase 2: ensure every target has a same-version A record.

    Glue A from the SRV reply is reused; every missing target is queried
    concurrently.  All workers share the same round deadline (2s from the very
    first upstream query), including their retries.
    """
    found: dict[str, dict] = {}
    pending: list[str] = []
    for target in targets:
        key = target.rstrip(".").lower()
        if key in glue:
            ip, ttl = glue[key]
            found[key] = {"type": "A", "name": target, "ttl": ttl, "ip": ip}
        else:
            pending.append(target)

    if not pending:
        return list(found.values()), "glue"

    def worker(target: str) -> dict | None:
        while deadline - time.monotonic() > 0.02:
            resp = query_with_retry(target, "A", deadline)
            if resp is None:
                return None  # shared budget exhausted
            if resp.header.rcode != RCODE.NOERROR:
                return None
            if _extract_version(resp) != version:
                # Different config generation: discard and retry while the
                # budget allows, so a mixed-version set is never assembled.
                if deadline - time.monotonic() <= 0.02:
                    return None
                continue
            a_rrs = [rr for rr in resp.rr if rr.rtype == QTYPE.A]
            if not a_rrs:
                return None
            rr = a_rrs[0]
            return {"type": "A", "name": target, "ttl": int(rr.ttl),
                    "ip": str(rr.rdata)}
        return None

    with ThreadPoolExecutor(max_workers=len(pending)) as pool:
        futures = {pool.submit(worker, t): t for t in pending}
        for fut, target in futures.items():
            rec = fut.result()
            if rec is None:
                return None, f"target {target} unresolved within budget"
            found[target.rstrip(".").lower()] = rec
    return list(found.values()), "concurrent-backfill"


def fetch_group() -> tuple[list[dict] | None, int | None, str]:
    """Run one complete resolution round under one shared 2s budget."""
    deadline = time.monotonic() + common.FETCH_BUDGET

    phase1 = _fetch_srv_phase(deadline)
    if phase1 is None:
        return None, None, "SRV phase failed within budget"
    srv_records, version, glue = phase1

    targets = [r["target"] for r in srv_records]
    a_records, how = _fetch_a_phase(targets, version, glue, deadline)
    if a_records is None:
        return None, version, how

    if len({r["name"] for r in a_records}) != len(targets):
        return None, version, "incomplete A set"

    return srv_records + a_records, version, f"complete v={version} ({how})"


# --------------------------------------------------------------------------
# Single-flight: concurrent cache-miss clients share one upstream round
# --------------------------------------------------------------------------
_flight_lock = threading.Lock()
_flight_event: threading.Event | None = None


def _cached_reply(query: DNSRecord, row: dict):
    remaining = row["group_until"] - time.time()
    ttl = max(1, int(math.ceil(remaining)))
    records = []
    for rec in row["records"]:
        capped = dict(rec)
        capped["reply_ttl"] = min(int(rec["ttl"]), ttl)
        records.append(capped)
    return _reply(
        query, RCODE.NOERROR, records, "cache-fresh",
        f"group v={row['version']} left={remaining:.1f}s")


def resolve_srv(query: DNSRecord):
    now = time.time()
    row = common.get_srv_cache()
    if row and now < row["group_until"]:
        return _cached_reply(query, row), "cache-fresh", "fresh SRV group from cache"

    # Cache miss/expiry: join an in-flight round or lead a new one.
    global _flight_event
    with _flight_lock:
        fresh = common.get_srv_cache()
        if fresh and time.time() < fresh["group_until"]:
            return _cached_reply(query, fresh), "cache-fresh", "fresh group (joined)"
        if _flight_event is not None:
            event, leader = _flight_event, False
        else:
            event = threading.Event()
            _flight_event = event
            leader = True

    if not leader:
        # Wake as soon as the shared round ends (success or failure); the
        # event is always set by the leader in its finally block.
        event.wait(timeout=common.FETCH_BUDGET + 3)
        row = common.get_srv_cache()
        if row and time.time() < row["group_until"]:
            return _cached_reply(query, row), "cache-fresh", "fresh group (shared flight)"
        return (_reply(query, RCODE.SERVFAIL, [], "none",
                       "shared round failed within budget"),
                "none", "upstream round incomplete; no SRV/A served")

    try:
        records, version, detail = fetch_group()
        if records is None:
            return (_reply(query, RCODE.SERVFAIL, [], "none", detail),
                    "none", f"incomplete same-version result: {detail}")
        fetched_at = time.time()
        row = common.put_srv_cache(version, records, fetched_at)
        fresh_records = [dict(r, reply_ttl=r["ttl"]) for r in row["records"]]
        return (_reply(query, RCODE.NOERROR, fresh_records, "upstream", detail),
                "upstream", f"cached atomic group {detail}")
    finally:
        with _flight_lock:
            _flight_event = None
        event.set()  # release every waiting client immediately


# --------------------------------------------------------------------------
# Plain service.example A path (unchanged semantics, its own cache)
# --------------------------------------------------------------------------
def resolve_a(query: DNSRecord):
    now = time.time()
    row = common.get_a_cache()
    if row and now < row["fresh_until"]:
        ttl = max(1, int(math.ceil(row["fresh_until"] - now)))
        return (_reply(query, RCODE.NOERROR,
                       [{"type": "A", "name": common.FQDN, "ttl": ttl,
                         "ip": row["ip"], "reply_ttl": ttl}],
                       "cache-fresh", f"left={row['fresh_until'] - now:.1f}s"),
                "cache-fresh", "fresh A from cache")

    deadline = time.monotonic() + common.FETCH_BUDGET
    resp = query_with_retry(common.FQDN, "A", deadline)
    if resp is not None and resp.header.rcode == RCODE.NOERROR:
        ips = [str(rr.rdata) for rr in resp.rr if rr.rtype == QTYPE.A]
        if ips:
            common.put_a_cache(ips[0], time.time())
            return (_reply(query, RCODE.NOERROR,
                           [{"type": "A", "name": common.FQDN,
                             "ttl": common.A_TTL, "ip": ips[0],
                             "reply_ttl": common.A_TTL}],
                           "upstream", f"fetched A={ips[0]}"),
                    "upstream", f"fetched A={ips[0]}")
    return (_reply(query, RCODE.SERVFAIL, [], "none", "upstream timeout"),
            "none", "A query: no usable upstream answer within budget")


# --------------------------------------------------------------------------
# UDP front end
# --------------------------------------------------------------------------
def handle_packet(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        name = qname.rstrip(".").lower()

        if name == common.SRV_OWNER.lower():
            if query.q.qtype == QTYPE.SRV:
                rep, source, detail = resolve_srv(query)
            else:
                rep = _reply(query, RCODE.NOERROR, [], "none", "nodata")
                source, detail = "none", "nodata for this qtype"
        elif name == common.FIXED_DOMAIN.lower() and query.q.qtype in (QTYPE.A, QTYPE.ANY):
            rep, source, detail = resolve_a(query)
        else:
            rep = _reply(query, RCODE.REFUSED, [], "none", "out-of-scope")
            source, detail = "none", "out-of-scope"

        sock.sendto(rep.pack(), addr)
        answers = ";".join(
            f"{QTYPE[rr.rtype]}={rr.rdata}(ttl={rr.ttl})" for rr in rep.rr
        ) or "-"
        common.log_query(qname, qtype, source, RCODE[rep.header.rcode], answers, detail)
    except Exception:
        common.log_query(qname, qtype, "error", "SERVFAIL", "-",
                         traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.RESOLVER_PORT))
    print(
        f"[resolver] SRV {common.SRV_NAME} / A {common.FQDN}"
        f" on udp/{common.RESOLVER_PORT}, upstream {common.AUTH_HOST}:{common.AUTH_PORT},"
        f" shared budget={common.FETCH_BUDGET}s (SRV ttl {common.SRV_TTL}s,"
        f" glue ttl {common.GLUE_TTL}s)",
        flush=True,
    )
    while True:
        data, addr = sock.recvfrom(4096)
        _CLIENT_POOL.submit(handle_packet, data, addr, sock)


if __name__ == "__main__":
    main()
