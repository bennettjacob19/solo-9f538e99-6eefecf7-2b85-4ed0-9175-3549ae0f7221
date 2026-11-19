#!/usr/bin/env python3
"""End-to-end self-test for the atomic SRV-group DNS duty system.

Spawns auth + resolver + web on loopback with the production semantics
(shared 2s fetch budget; SRV TTL 10s vs glue A TTL 5s so the group's
min-expiry rule is observable) and drives every requirement:

  A. one UDP SRV reply carries both targets (priority/port) + glue A;
     cache hit serves the same group with counting TTL; expiry re-fetches.
  B. omitting the additional A makes the resolver back-fill both A records
     concurrently, still inside the shared budget.
  C. dropped / delayed authoritative answers -> SERVFAIL with neither SRV nor
     A, nothing cached, elapsed bounded by the shared 2s budget.
  D. a config change in the middle of a round (version skew) is rejected:
     no mixed-version answer and no cache entry.
  E. the whole group expires at the earliest record expiry; every answered
     RR is capped to the remaining group TTL; restart keeps absolute deadlines.
  F. the plain service.example A query path still works independently.
  G. web console smoke test (page, config edit + version bump, real query).

Exits non-zero if any check fails.  Runtime: ~20s.
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dnslib import QTYPE, DNSRecord  # noqa: E402

DOMAIN = "service.example"
SRV_NAME = f"_ldap._tcp.{DOMAIN}."
T1, T2 = f"ldap1.{DOMAIN}.", f"ldap2.{DOMAIN}."
AUTH_PORT, RES_PORT, WEB_PORT = 15354, 15353, 18000
TMP = tempfile.mkdtemp(prefix="dns-srv-selftest-")
DB = os.path.join(TMP, "app.db")

env = dict(os.environ)
env.update(
    DB_PATH=DB,
    FIXED_DOMAIN=DOMAIN,
    AUTH_HOST="127.0.0.1",
    AUTH_PORT=str(AUTH_PORT),
    RESOLVER_HOST="127.0.0.1",
    RESOLVER_PORT=str(RES_PORT),
    WEB_PORT=str(WEB_PORT),
    FETCH_BUDGET="2",
    SRV_TTL="10",
    GLUE_TTL="5",
    A_TTL="5",
    DEFAULT_IP1="192.0.2.11",
    DEFAULT_IP2="192.0.2.12",
    DEFAULT_PORT1="389",
    DEFAULT_PORT2="3890",
    DEFAULT_DELAY="3",
    PYTHONPATH=ROOT,
    PYTHONUNBUFFERED="1",
)
procs: dict[str, subprocess.Popen] = {}
FAILS: list[str] = []


def _kill_port_holders() -> None:
    """Abort early if another process already holds a test UDP port: with
    SO_REUSEADDR two UDP sockets may bind the same port and the kernel would
    then split datagrams between them, making the test nondeterministic."""
    for port in (AUTH_PORT, RES_PORT):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            probe.bind(("127.0.0.1", port))
        except OSError:
            probe.close()
            raise SystemExit(
                f"port {port} is already in use; kill stale resolver/auth "
                f"processes before running the self-test")
        else:
            probe.close()


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def start(name: str, module: str) -> None:
    log = open(os.path.join(TMP, f"{name}.log"), "ab")
    procs[name] = subprocess.Popen(
        [sys.executable, "-m", module],
        cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
    )


def stop(name: str) -> None:
    p = procs.get(name)
    if p and p.poll() is None:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(5)
    if p is not None:
        procs.pop(name, None)


def set_config(**fields) -> int:
    """Write the control table directly and return the new version."""
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    sets = ", ".join(f"{k} = ?" for k in fields)
    vals = list(fields.values())
    conn.execute(
        f"UPDATE control SET {sets}, version = version + 1, updated_at = ?"
        " WHERE id = 1",
        vals + [time.time()],
    )
    conn.commit()
    ver = conn.execute("SELECT version FROM control WHERE id = 1").fetchone()[0]
    conn.close()
    return ver


def get_control() -> dict:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM control WHERE id = 1").fetchone()
    conn.close()
    return dict(row)


def get_srv_cache() -> dict | None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM srv_cache WHERE id = 1").fetchone()
    conn.close()
    if not row:
        return None
    out = dict(row)
    out["records"] = json.loads(out["records"])
    return out


def clear_srv_cache() -> None:
    conn = sqlite3.connect(DB, timeout=15)
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("DELETE FROM srv_cache WHERE id = 1")
    conn.commit()
    conn.close()


def dns_query(qname: str = SRV_NAME, qtype: str = "SRV",
              timeout: float = 10) -> tuple[int, list[dict], str | None, list[str]]:
    q = DNSRecord.question(qname, qtype)
    data = q.send("127.0.0.1", RES_PORT, timeout=timeout)
    rep = DNSRecord.parse(data)
    answers = []
    for rr in rep.rr:
        item = {"type": QTYPE[rr.rtype], "ttl": rr.ttl, "rname": str(rr.rname)}
        if rr.rtype == QTYPE.SRV:
            item.update(priority=int(rr.rdata.priority),
                        weight=int(rr.rdata.weight),
                        port=int(rr.rdata.port),
                        target=str(rr.rdata.target))
        else:
            item["ip"] = str(rr.rdata)
        answers.append(item)
    ar_txt = [str(rr.rdata).strip('"') for rr in rep.ar if rr.rtype == QTYPE.TXT]
    src = next((t.split("=", 1)[1].split()[0] for t in ar_txt
                if t.startswith("source=")), None)
    return rep.header.rcode, answers, src, ar_txt


def check(name: str, cond: bool, info: str = "") -> None:
    print(f"  [{'PASS' if cond else 'FAIL'}] {name} {info}", flush=True)
    if not cond:
        FAILS.append(name)


def wait_ready(timeout: float = 25) -> bool:
    """Readiness probe that never sends a DNS question: merely touching the
    resolver's UDP port would trigger (and perturb) a real cache round."""
    t0 = time.time()
    probe = DNSRecord.question("ready.probe.", "A").pack()
    while time.time() - t0 < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.0)
            s.sendto(probe, ("127.0.0.1", RES_PORT))
            s.recvfrom(4096)
            s.close()
            return True
        except Exception:
            time.sleep(0.3)
    return False


def wait_web_ready(timeout: float = 25) -> bool:
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def srv_by_prio(answers: list[dict]) -> dict:
    return {a["priority"]: a for a in answers if a["type"] == "SRV"}


def a_map(answers: list[dict]) -> dict:
    return {a["rname"]: a for a in answers if a["type"] == "A"}


# --------------------------------------------------------------------------
# scenario
# --------------------------------------------------------------------------
def main() -> int:
    print(f"[selftest] workdir={TMP}", flush=True)
    _kill_port_holders()
    start("auth", "app.auth_server")
    start("resolver", "app.resolver")
    start("web", "app.web")
    try:
        if not (wait_ready() and wait_web_ready()):
            print("  [FAIL] services did not come up")
            return 1

        # -- A. full SRV answer in one round; fresh cache; expiry re-fetch ----
        print("A. 一次答复给齐主备 SRV + 附加 A；缓存与到期重查", flush=True)
        clear_srv_cache()
        set_config(mode="ok", include_glue_a=1,
                   t1_ip="192.0.2.11", t1_port=389,
                   t2_ip="192.0.2.12", t2_port=3890)
        t0 = time.time()
        rc, ans, src, ar = dns_query()
        elapsed = time.time() - t0
        srvs, amap = srv_by_prio(ans), a_map(ans)
        check("A1 NOERROR + 上游来源", rc == 0 and src == "upstream",
              f"rcode={rc} src={src}")
        check("A2 主备两条 SRV（优先级/端口）",
              set(srvs) == {10, 20}
              and srvs[10]["port"] == 389 and srvs[20]["port"] == 3890
              and srvs[10]["target"] == T1 and srvs[20]["target"] == T2,
              f"srvs={list(srvs.values())}")
        check("A3 附加 A 随同一答复给齐",
              amap.get(T1, {}).get("ip") == "192.0.2.11"
              and amap.get(T2, {}).get("ip") == "192.0.2.12",
              f"a={list(amap.values())}")
        check("A4 内部版本 TXT 不泄露给客户端",
              all(not t.startswith("v=") for t in ar), f"ar={ar}")
        check("A5 回源在共享预算内完成", elapsed < 2.0, f"elapsed={elapsed:.2f}s")

        rc, ans, src, _ = dns_query()
        check("A6 第二次命中整组缓存", rc == 0 and src == "cache-fresh",
              f"src={src}")
        check("A7 缓存答复仍含 2 SRV + 2 A",
              len(srv_by_prio(ans)) == 2 and len(a_map(ans)) == 2,
              f"ans={ans}")

        new_ver = set_config(t1_port=1389, t2_port=2389)
        rc, ans, src, _ = dns_query()
        check("A8 缓存未到期时仍给旧端口",
              src == "cache-fresh" and srv_by_prio(ans)[10]["port"] == 389,
              f"src={src}")
        cache = get_srv_cache()
        group_until = cache["group_until"]
        time.sleep(max(0.2, group_until - time.time() + 0.3))  # wait whole-group expiry
        rc, ans, src, _ = dns_query()
        check("A9 到期整组重查，拿到新端口",
              rc == 0 and src == "upstream"
              and srv_by_prio(ans)[10]["port"] == 1389
              and srv_by_prio(ans)[20]["port"] == 2389,
              f"src={src}")
        check("A10 新缓存版本号已更新",
              get_srv_cache()["version"] == new_ver,
              f"cache_ver={get_srv_cache()['version']} expect={new_ver}")

        # -- B. omitted additional A -> concurrent back-fill ------------------
        print("B. 权威端省略附加 A：解析器并发补查两个目标", flush=True)
        clear_srv_cache()
        set_config(mode="ok", include_glue_a=0)
        t0 = time.time()
        rc, ans, src, _ = dns_query()
        elapsed = time.time() - t0
        amap = a_map(ans)
        check("B1 补查后仍返回完整组（2 SRV + 2 A）",
              rc == 0 and len(srv_by_prio(ans)) == 2
              and amap.get(T1, {}).get("ip") == "192.0.2.11"
              and amap.get(T2, {}).get("ip") == "192.0.2.12",
              f"rcode={rc} ans={ans}")
        check("B2 并发补查在 2s 预算内", src == "upstream" and elapsed < 2.0,
              f"src={src} elapsed={elapsed:.2f}s")
        check("B3 完整同版结果已写入缓存", get_srv_cache() is not None)

        # -- C. budget exhaustion -> SERVFAIL without SRV/A, nothing cached ----
        print("C. 时限内收不齐 -> 不含 SRV/A 的 SERVFAIL，且不写缓存", flush=True)
        clear_srv_cache()
        set_config(mode="drop")
        t0 = time.time()
        rc, ans, src, _ = dns_query()
        elapsed = time.time() - t0
        check("C1 丢包 -> SERVFAIL", rc == 2, f"rcode={rc}")
        check("C2 SERVFAIL 不含任何 SRV/A", len(ans) == 0, f"ans={ans}")
        check("C3 答复来源 none", src == "none", f"src={src}")
        check("C4 耗时受 2s 共享预算约束", 1.8 <= elapsed <= 3.2,
              f"elapsed={elapsed:.2f}s")
        check("C5 失败结果不写缓存", get_srv_cache() is None)

        set_config(mode="delay", delay_seconds=2.5)  # > 2s budget
        t0 = time.time()
        rc, ans, src, _ = dns_query()
        elapsed = time.time() - t0
        check("C6 延迟超预算同样 SERVFAIL 且无记录",
              rc == 2 and len(ans) == 0 and src == "none",
              f"rcode={rc} ans={ans} elapsed={elapsed:.2f}s")
        check("C7 延迟场景也不写缓存", get_srv_cache() is None)

        # back-fill half failing: SRV healthy without glue, target-2 A dropped.
        set_config(mode="ok", include_glue_a=0, t2_mode="drop")
        clear_srv_cache()
        t0 = time.time()
        rc, ans, src, _ = dns_query()
        elapsed = time.time() - t0
        check("C8 补查阶段单目标丢包 -> SERVFAIL、无 SRV/A、不缓存",
              rc == 2 and len(ans) == 0 and src == "none"
              and get_srv_cache() is None and 1.8 <= elapsed <= 3.2,
              f"rcode={rc} ans={ans} elapsed={elapsed:.2f}s")

        # -- D. version skew: mixed-generation records are rejected -----------
        print("D. 配置版本交错：非同版完整结果一律不答复、不缓存", flush=True)
        set_config(mode="ok", include_glue_a=0, t2_mode="stale_version",
                   t1_ip="192.0.2.11", t2_ip="192.0.2.12")
        clear_srv_cache()
        ctl = get_control()
        v_cur = ctl["version"]
        check("D0 目标 2 被配置为永远回上一版", ctl["t2_mode"] == "stale_version")

        t0 = time.time()
        rc, ans, src, _ = dns_query()
        elapsed = time.time() - t0
        check("D1 混版（SRV 为 v%d，目标2 A 为 v%d）被拒绝" % (v_cur, v_cur - 1),
              rc == 2 and len(ans) == 0, f"rcode={rc} ans={ans}")
        check("D2 混版轮次不写缓存", get_srv_cache() is None)
        check("D3 反复重试到预算耗尽，总耗时受 2s 约束",
              1.8 <= elapsed <= 3.2, f"elapsed={elapsed:.2f}s")

        # restore the target-2 path; the next round must complete cleanly.
        # Changing t2_ip as well guarantees the new version can never equal
        # the stale generation produced by stale_version mode.
        set_config(t2_mode="ok", t2_ip="192.0.2.99")
        rc, ans, src, _ = dns_query()
        check("D4 恢复同版后即可正常回源并缓存",
              rc == 0 and src == "upstream" and get_srv_cache() is not None
              and a_map(ans).get(T2, {}).get("ip") == "192.0.2.99",
              f"rcode={rc} src={src}")
        set_config(t2_ip="192.0.2.12")  # back to the documented default

        # -- E. group TTL = earliest record; restart keeps absolute deadline ---
        print("E. 最早到期记录决定整组期限；重启不延长", flush=True)
        set_config(mode="ok", include_glue_a=1)
        clear_srv_cache()
        rc, ans, src, _ = dns_query()
        assert rc == 0 and src == "upstream"
        ttl_srv = srv_by_prio(ans)[10]["ttl"]
        ttl_a = a_map(ans)[T1]["ttl"]
        check("E1 权威侧 SRV/附加 A TTL 不同（10 vs 5）",
              ttl_srv == 10 and ttl_a == 5, f"srv={ttl_srv} a={ttl_a}")
        cache = get_srv_cache()
        expected_until = cache["fetched_at"] + 5  # glue A is the earliest
        check("E2 整组期限=最早到期记录（A 的 5s）",
              abs(cache["group_until"] - expected_until) < 0.5,
              f"group_until={cache['group_until']} expected~{expected_until}")

        # Restart immediately while the group is almost fully fresh, so the
        # absolute deadline is guaranteed to still be in the future afterwards.
        stop("resolver")
        time.sleep(0.5)
        deadline_before = get_srv_cache()["group_until"]
        start("resolver", "app.resolver")
        assert wait_ready(), "resolver did not come back"
        deadline_after = get_srv_cache()["group_until"]
        check("E3 重启不改变持久化的绝对期限（不重新计时）",
              abs(deadline_after - deadline_before) < 1e-6,
              f"{deadline_before} -> {deadline_after}")
        assert time.time() < deadline_after, "group expired during restart"
        rc, ans, src, _ = dns_query()
        check("E3b 期限内重启后仍命中同组缓存",
              src == "cache-fresh", f"src={src}")

        time.sleep(2.2)
        rc, ans, src, _ = dns_query()
        remaining = get_srv_cache()["group_until"] - time.time()
        srvs, amap = srv_by_prio(ans), a_map(ans)
        check("E4 缓存命中且每条 RR 的 TTL 都被压到整组剩余期限",
              src == "cache-fresh"
              and all(1 <= a["ttl"] <= max(1, int(remaining + 1.5)) for a in ans)
              and srvs[10]["ttl"] <= 6 and amap[T1]["ttl"] <= 4,
              f"ttls={[a['ttl'] for a in ans]} left={remaining:.1f}")

        time.sleep(max(0.2, get_srv_cache()["group_until"] - time.time() + 0.3))
        set_config(mode="ok", t2_mode="ok")  # healthy upstream for the re-fetch
        rc, ans, src, _ = dns_query()
        check("E5 到期后整组重查成功", rc == 0 and src == "upstream"
              and len(srv_by_prio(ans)) == 2 and len(a_map(ans)) == 2,
              f"rcode={rc} src={src}")

        # -- F. plain service.example A path stays independent -----------------
        print("F. 原 service.example 的 A 查询照常", flush=True)
        rc, ans, src, _ = dns_query(f"{DOMAIN}.", "A")
        check("F1 A 查询 NOERROR", rc == 0 and len(ans) == 1
              and ans[0]["ip"] == "192.0.2.10", f"rcode={rc} ans={ans}")
        rc, ans, src, _ = dns_query(f"{DOMAIN}.", "A")
        check("F2 A 路径独立缓存", src == "cache-fresh", f"src={src}")

        rc, ans, _, _ = dns_query("other.example.", "A")
        check("F3 范围外名称 REFUSED", rc == 5, f"rcode={rc}")
        rc, ans, _, _ = dns_query(SRV_NAME, "TXT")
        check("F4 SRV 名称的非 SRV 查询 NODATA", rc == 0 and len(ans) == 0,
              f"rcode={rc} ans={ans}")

        # -- G. web console smoke test ----------------------------------------
        print("G. 网页控制台冒烟", flush=True)
        with urllib.request.urlopen(f"http://127.0.0.1:{WEB_PORT}/",
                                    timeout=5) as r:
            body = r.read().decode()
        check("G1 主页可访问", r.status == 200 and "SRV" in body)

        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/config",
            data=json.dumps({"t1_ip": "192.0.2.77", "t1_port": 636,
                             "include_glue_a": False}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            res = json.load(r)
        ctl = get_control()
        check("G2 网页保存配置并 bump 版本",
              res["ok"] and ctl["t1_ip"] == "192.0.2.77"
              and ctl["t1_port"] == 636 and ctl["include_glue_a"] == 0,
              f"ctl={ctl}")

        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/config",
            data=json.dumps({"t1_ip": "999.1.1.1"}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
            check("G3 非法 IPv4 被拒绝", False)
        except urllib.error.HTTPError as e:
            check("G3 非法 IPv4 被拒绝", e.code == 400)

        req = urllib.request.Request(
            f"http://127.0.0.1:{WEB_PORT}/api/query?qtype=SRV", method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            res = json.load(r)
        srv_ans = [a for a in res["answers"] if a["type"] == "SRV"]
        check("G4 网页发起真实 SRV 查询并展示答复/TTL/来源",
              res["ok"] and res["rcode"] == "NOERROR" and len(srv_ans) == 2
              and srv_ans[0]["priority"] in (10, 20)
              and all(a["ttl"] >= 1 for a in res["answers"])
              and res["source"] in ("upstream", "cache-fresh"),
              f"res={res.get('rcode')} src={res.get('source')}")

        with urllib.request.urlopen(
                f"http://127.0.0.1:{WEB_PORT}/api/state", timeout=5) as r:
            st = json.load(r)
        check("G5 状态接口含控制/整组缓存/双方日志",
              st["control"] and st["srv_cache"] and st["a_cache"]
              and len(st["resolver_log"]) > 0 and len(st["auth_log"]) > 0)
    finally:
        for name in list(procs):
            stop(name)
        print(f"[selftest] logs in {TMP}", flush=True)

    print(f"\n{'=' * 60}\n结果: {len(FAILS)} 项失败" if FAILS
          else f"\n{'=' * 60}\n结果: 全部通过", flush=True)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
