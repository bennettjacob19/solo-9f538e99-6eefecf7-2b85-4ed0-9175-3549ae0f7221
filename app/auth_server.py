"""Local authoritative endpoint for the SRV duty exercise.

Serves, under one fixed zone, three question kinds:

  SRV  _ldap._tcp.<domain>   -> two SRV RRs (primary/backup with priority and
                                port), plus the targets' glue A records in the
                                *additional* section unless the web console has
                                asked for them to be omitted.
  A    ldap1/ldap2.<domain>  -> the configured target IPv4 (so the resolver can
                                concurrently back-fill missing glue).
  A    <domain>              -> the plain service A record (unchanged path).

Every answer additionally carries a TXT record

    _cfgver.<domain>.  TXT  "v=<version>"

so the resolver can prove that all records of one answer round come from the
same generation of the authoritative configuration.  A config edit on the web
console bumps `version` atomically; a round that mixes versions cannot be
answered or cached.

Failure injection, switched live from the web console:
  ok    -- answer immediately
  delay -- sleep delay_seconds before answering (longer than the 2s budget)
  drop  -- never answer (simulates the lost authoritative endpoint)

Every received query is logged to auth_log.
"""
from __future__ import annotations

import socket
import time
import traceback
from concurrent.futures import ThreadPoolExecutor

from dnslib import A, QTYPE, RCODE, RR, SRV, TXT, DNSRecord

from . import common

# Bounded shared pool: a storm of retries must not exhaust thread creation.
# Tasks are cheap (one datagram, possibly one sleep); back-pressure simply
# queues them instead of spawning unbounded threads.
_POOL = ThreadPoolExecutor(max_workers=32, thread_name_prefix="auth")


def _version_txt(version: int) -> RR:
    return RR(common.VERSION_NAME, QTYPE.TXT, ttl=0,
              rdata=TXT(f"v={int(version)}"))


def _maybe_delay_or_drop(qname: str, qtype: str, ctl: dict, sock, addr) -> bool:
    """Return True when the query must be dropped (no answer at all)."""
    mode = ctl["mode"]
    if mode == "drop":
        common.log_auth(qname, qtype, mode, "dropped",
                        "simulating lost authoritative endpoint")
        return True
    if mode == "delay":
        time.sleep(max(0.0, float(ctl["delay_seconds"])))
    return False


def handle(data: bytes, addr, sock: socket.socket) -> None:
    qname = qtype = "?"
    mode = "?"
    try:
        query = DNSRecord.parse(data)
        qname = str(query.q.qname)
        qtype = QTYPE[query.q.qtype]
        ctl = common.get_control() or {
            "mode": "ok", "t2_mode": "ok",
            "delay_seconds": common.DEFAULT_DELAY,
            "include_glue_a": 1,
            "t1_ip": common.DEFAULT_IP1, "t1_port": common.DEFAULT_PORT1,
            "t2_ip": common.DEFAULT_IP2, "t2_port": common.DEFAULT_PORT2,
            "version": 1,
        }
        mode = ctl["mode"]
        name = qname.rstrip(".").lower()

        # ---- SRV question: the heart of the exercise ----------------------
        if name == common.SRV_OWNER.lower() and query.q.qtype == QTYPE.SRV:
            if _maybe_delay_or_drop(qname, qtype, ctl, sock, addr):
                return
            rep = query.reply()
            rep.add_answer(RR(common.SRV_NAME, QTYPE.SRV, ttl=common.SRV_TTL,
                              rdata=SRV(10, 0, int(ctl["t1_port"]), common.TARGET1)))
            rep.add_answer(RR(common.SRV_NAME, QTYPE.SRV, ttl=common.SRV_TTL,
                              rdata=SRV(20, 0, int(ctl["t2_port"]), common.TARGET2)))
            if int(ctl["include_glue_a"]):
                rep.add_ar(RR(common.TARGET1, QTYPE.A, ttl=common.GLUE_TTL,
                              rdata=A(ctl["t1_ip"])))
                rep.add_ar(RR(common.TARGET2, QTYPE.A, ttl=common.GLUE_TTL,
                              rdata=A(ctl["t2_ip"])))
                glue = f" glue A {ctl['t1_ip']},{ctl['t2_ip']}"
            else:
                glue = " glue A omitted"
            rep.add_ar(_version_txt(ctl["version"]))
            sock.sendto(rep.pack(), addr)
            common.log_auth(
                qname, qtype, mode, "answered",
                f"SRV prio 10/{ctl['t1_port']} 20/{ctl['t2_port']}{glue}"
                f" v={ctl['version']}")
            return

        # ---- A question for one of the two SRV targets --------------------
        target_ips = {
            common.TARGET1.rstrip(".").lower(): ctl["t1_ip"],
            common.TARGET2.rstrip(".").lower(): ctl["t2_ip"],
        }
        if name in target_ips and query.q.qtype in (QTYPE.A, QTYPE.ANY):
            if _maybe_delay_or_drop(qname, qtype, ctl, sock, addr):
                return
            is_target2 = name == common.TARGET2.rstrip(".").lower()
            t2_mode = ctl.get("t2_mode", "ok")
            if is_target2 and t2_mode == "drop":
                # Deterministic failure of one back-fill target: the resolver
                # cannot complete the group inside the shared budget.
                common.log_auth(qname, qtype, t2_mode, "dropped",
                                "target-2 A injected loss")
                return
            rep = query.reply()
            rep.add_answer(RR(qname, QTYPE.A, ttl=common.GLUE_TTL,
                              rdata=A(target_ips[name])))
            if is_target2 and t2_mode == "stale_version":
                # Always answer with the previous generation's version, so a
                # back-fill round can only ever assemble a mixed-version set.
                anno = max(1, int(ctl["version"]) - 1)
                tag = f" stale v={anno} (current v={ctl['version']})"
            else:
                anno = int(ctl["version"])
                tag = ""
            rep.add_ar(_version_txt(anno))
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "answered",
                            f"A={target_ips[name]} v={anno}{tag}")
            return

        # ---- plain A question for the service apex ------------------------
        if name == common.FIXED_DOMAIN.lower() and query.q.qtype in (QTYPE.A, QTYPE.ANY):
            if _maybe_delay_or_drop(qname, qtype, ctl, sock, addr):
                return
            rep = query.reply()
            rep.add_answer(RR(common.FQDN, QTYPE.A, ttl=common.A_TTL,
                              rdata=A(common.DEFAULT_APEX_IP)))
            rep.add_ar(_version_txt(ctl["version"]))
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "answered",
                            f"A={common.DEFAULT_APEX_IP} v={ctl['version']}")
            return

        # ---- anything else in the zone: authoritative NODATA/NXDOMAIN -----
        if name.endswith(common.FIXED_DOMAIN.lower()):
            rep = query.reply()
            rep.header.rcode = RCODE.NOERROR  # name exists, no data of this qtype
            sock.sendto(rep.pack(), addr)
            common.log_auth(qname, qtype, mode, "nodata", "in-zone, unsupported qtype/name")
            return

        rep = query.reply()
        rep.header.rcode = RCODE.REFUSED
        sock.sendto(rep.pack(), addr)
        common.log_auth(qname, qtype, mode, "refused", "out-of-zone name")
    except Exception:
        common.log_auth(qname, qtype, mode, "error", traceback.format_exc(limit=3))


def main() -> None:
    common.init_db()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", common.AUTH_PORT))
    print(f"[auth] authoritative for {common.FQDN} (SRV owner {common.SRV_NAME})"
          f" on udp/{common.AUTH_PORT}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        _POOL.submit(handle, data, addr, sock)


if __name__ == "__main__":
    main()
