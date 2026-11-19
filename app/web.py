"""FastAPI operations console for the atomic SRV-group exercise.

Single-page console that can
  * edit both SRV targets' IPv4 addresses and ports (every edit bumps the
    authoritative config version atomically),
  * ask the authoritative endpoint to omit the additional A records from its
    SRV reply (forcing the resolver to back-fill A records concurrently),
  * inject failures (delayed / dropped answers) to exercise the shared 2s
    budget and the SERVFAIL path,
  * fire a *real* SRV (or plain A) query at the resolver and show the actual
    reply -- rcode, priorities, ports, addresses, per-RR TTL -- plus where it
    came from (upstream / cache-fresh / none),
  * show the atomic group cache (with live countdown) and both sides' logs.
"""
from __future__ import annotations

import ipaddress
import time

import uvicorn
from dnslib import QTYPE, RCODE, DNSRecord
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import common

app = FastAPI(title="DNS SRV duty console")

PAGE = """<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>DNS SRV 值班控制台</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; background:#f6f7f9; color:#222; }
  h1 { font-size: 1.3rem; }
  section { background:#fff; border:1px solid #ddd; border-radius:8px;
            padding:1rem 1.2rem; margin-bottom:1rem; }
  h2 { font-size:1rem; margin-top:0; }
  label { margin-right:1rem; cursor:pointer; }
  input[type=text] { width:9rem; }
  input[type=number] { width:5.5rem; }
  button { padding:.35rem 1rem; cursor:pointer; }
  table { border-collapse:collapse; width:100%; font-size:.82rem; }
  th, td { border:1px solid #e2e2e2; padding:.25rem .5rem; text-align:left; }
  th { background:#f0f1f4; }
  pre { background:#0d1420; color:#cfe3ff; padding:.7rem; border-radius:6px;
        overflow:auto; font-size:.78rem; }
  .pill { display:inline-block; padding:.1rem .55rem; border-radius:1rem;
          background:#e8ecf3; font-size:.8rem; margin-right:.4rem; }
  .ok { color:#0a7a2f; } .bad { color:#b00020; } .muted { color:#777; }
  #qresult b { font-size:1.05rem; }
</style>
</head>
<body>
<h1>DNS SRV 值班控制台 — <code id="dom">…</code></h1>
<p class="muted" id="params"></p>

<section>
  <h2>1. 权威端配置（每次保存都会使配置版本 +1）</h2>
  <table style="width:auto; margin-bottom:.6rem">
    <tr><th>目标</th><th>名称</th><th>IPv4</th><th>端口</th></tr>
    <tr><td>主 (priority 10)</td><td id="t1name">…</td>
        <td><input type="text" id="t1ip"></td><td><input type="number" id="t1port" min="1" max="65535"></td></tr>
    <tr><td>备 (priority 20)</td><td id="t2name">…</td>
        <td><input type="text" id="t2ip"></td><td><input type="number" id="t2port" min="1" max="65535"></td></tr>
  </table>
  <p>
    <label><input type="checkbox" id="glue"> SRV 答复中附带附加 A（取消勾选则省略，解析器需并发补查）</label>
  </p>
  <p>
    故障注入（整端）：
    <label><input type="radio" name="mode" value="ok"> 正常</label>
    <label><input type="radio" name="mode" value="delay"> 延迟应答</label>
    <label><input type="radio" name="mode" value="drop"> 丢包不应答</label>
    &nbsp; 延迟秒数：<input type="number" id="delay" value="3" min="0" step="0.5">
  </p>
  <p>
    目标 2 的 A 查询单独注入（仅在省略附加 A、需要补查时生效）：
    <label><input type="radio" name="t2mode" value="ok"> 正常</label>
    <label><input type="radio" name="t2mode" value="drop"> 丢包</label>
    <label><input type="radio" name="t2mode" value="stale_version"> 旧版本号</label>
    &nbsp; <button onclick="applyConfig()">保存配置</button>
    <span id="modemsg"></span>
  </p>
  <p class="muted">当前版本：<b id="curver">…</b> · 模式：<b id="curmode">…</b>
     · 附加 A：<b id="curglue">…</b>（每 2 秒自动刷新）</p>
</section>

<section>
  <h2>2. 发起真实 DNS 查询（经解析器）</h2>
  <button onclick="doQuery('SRV')">查询 SRV（_ldap._tcp…）</button>
  <button onclick="doQuery('A')">查询 A（service.example）</button>
  <span id="qmsg"></span>
  <div id="qresult"></div>
  <pre id="qraw" style="display:none"></pre>
</section>

<section>
  <h2>3. 解析器缓存状态</h2>
  <div id="srvcache">…</div>
  <div id="acache" style="margin-top:.5rem">…</div>
</section>

<section>
  <h2>4. 解析器查询日志（最近 15 条）</h2>
  <table id="rlog"><thead><tr>
    <th>时间</th><th>名称</th><th>类型</th><th>来源</th><th>RCODE</th><th>答复</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<section>
  <h2>5. 权威端接收日志（最近 15 条）</h2>
  <table id="alog"><thead><tr>
    <th>时间</th><th>名称</th><th>类型</th><th>模式</th><th>动作</th><th>说明</th>
  </tr></thead><tbody></tbody></table>
</section>

<script>
let serverOffset = 0;

function fmtTs(ts) { return new Date(ts * 1000).toLocaleTimeString(); }
function countdown(ts) {
  const left = ts - (Date.now() / 1000 + serverOffset);
  if (left <= 0) return '<span class="bad">已到期（整组重查）</span>';
  return '<span class="ok">剩 ' + left.toFixed(1) + 's</span>';
}

async function refresh() {
  try {
    const s = await (await fetch('/api/state')).json();
    serverOffset = s.now - Date.now() / 1000;
    document.getElementById('dom').textContent = s.srv_owner;
    document.getElementById('params').textContent =
      `共享回源预算=${s.params.fetch_budget}s（首次回源起，补查与重试共用）` +
      ` · 权威 SRV TTL=${s.params.srv_ttl}s · 附加 A TTL=${s.params.glue_ttl}s` +
      ` · 整组期限=组内最早到期记录`;
    const c = s.control;
    if (c) {
      document.getElementById('curver').textContent = 'v' + c.version;
      document.getElementById('curmode').textContent = c.mode;
      document.getElementById('curglue').textContent = c.include_glue_a ? '附带' : '省略';
      document.getElementById('t1name').textContent = s.targets[0];
      document.getElementById('t2name').textContent = s.targets[1];
      if (document.activeElement.id !== 't1ip') document.getElementById('t1ip').value = c.t1_ip;
      if (document.activeElement.id !== 't2ip') document.getElementById('t2ip').value = c.t2_ip;
      if (document.activeElement.id !== 't1port') document.getElementById('t1port').value = c.t1_port;
      if (document.activeElement.id !== 't2port') document.getElementById('t2port').value = c.t2_port;
      if (document.activeElement.id !== 'glue') document.getElementById('glue').checked = !!c.include_glue_a;
      if (!document.querySelector('input[name=mode]:focus'))
        document.querySelector(`input[name=mode][value=${c.mode}]`).checked = true;
      if (!document.querySelector('input[name=t2mode]:focus'))
        document.querySelector(`input[name=t2mode][value=${c.t2_mode}]`).checked = true;
      if (document.activeElement.id !== 'delay') document.getElementById('delay').value = c.delay_seconds;
    }
    const k = s.srv_cache;
    document.getElementById('srvcache').innerHTML = k ?
      `<span class="pill">SRV 整组 v=${k.version}</span>` +
      `<span class="pill">记录数=${k.records.length}</span>` +
      `<span class="pill">整组期限：${countdown(k.group_until)}</span>` +
      k.records.map(r => `<span class="pill">${r.type === 'SRV'
        ? 'SRV prio=' + r.priority + ' port=' + r.port + ' → ' + r.target
        : 'A ' + r.name + ' = ' + r.ip}（TTL ${r.ttl}s）</span>`).join(' ')
      : '<span class="muted">（SRV 缓存为空）</span>';
    const a = s.a_cache;
    document.getElementById('acache').innerHTML = a ?
      `<span class="pill">A ${a.qname} = ${a.ip}</span>` +
      `<span class="pill">期限：${countdown(a.fresh_until)}</span>`
      : '<span class="muted">（A 缓存为空）</span>';
    fillLog('rlog', s.resolver_log, r =>
      [fmtTs(r.ts), r.qname, r.qtype, r.source, r.rcode, r.answers, r.detail]);
    fillLog('alog', s.auth_log, r =>
      [fmtTs(r.ts), r.qname, r.qtype, r.mode, r.action, r.detail]);
  } catch (e) { console.log(e); }
}

function fillLog(id, rows, cols) {
  const tb = document.querySelector('#' + id + ' tbody');
  tb.innerHTML = rows.map(r =>
    '<tr>' + cols(r).map(x => `<td>${x ?? ''}</td>`).join('') + '</tr>').join('');
}

async function applyConfig() {
  const body = {
    mode: document.querySelector('input[name=mode]:checked').value,
    t2_mode: document.querySelector('input[name=t2mode]:checked').value,
    delay_seconds: parseFloat(document.getElementById('delay').value),
    include_glue_a: document.getElementById('glue').checked,
    t1_ip: document.getElementById('t1ip').value,
    t2_ip: document.getElementById('t2ip').value,
    t1_port: parseInt(document.getElementById('t1port').value, 10),
    t2_port: parseInt(document.getElementById('t2port').value, 10),
  };
  const r = await (await fetch('/api/config', { method: 'POST',
    headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body) })).json();
  document.getElementById('modemsg').textContent =
    r.ok ? ` ✔ 已保存，新版本 v${r.control.version}` : ' ✘ ' + r.error;
  refresh();
}

async function doQuery(qt) {
  document.getElementById('qmsg').textContent = ' 查询中…';
  const r = await (await fetch('/api/query?qtype=' + qt, {method: 'POST'})).json();
  document.getElementById('qmsg').textContent = '';
  const el = document.getElementById('qresult');
  if (!r.ok) { el.innerHTML = '<b class="bad">查询失败：' + r.error + '</b>'; return; }
  const ans = r.answers.length
    ? r.answers.map(a => {
        if (a.type === 'SRV')
          return `SRV prio=${a.priority} weight=${a.weight} port=<b>${a.port}</b> → ${a.target} <span class="muted">TTL=${a.ttl}s</span>`;
        return `${a.type} ${a.name} = ${a.data} <span class="muted">TTL=${a.ttl}s</span>`;
      }).join('，')
    : '（无应答记录）';
  const cls = r.rcode === 'NOERROR' ? 'ok' : 'bad';
  el.innerHTML = `<p><b class="${cls}">${r.rcode}</b> &nbsp; ${ans} &nbsp; ` +
    `<span class="pill">来源：${r.source}</span> ` +
    `<span class="muted">${r.elapsed_ms}ms · ${r.meta.join(' ')}</span></p>`;
  const raw = document.getElementById('qraw');
  raw.style.display = 'block';
  raw.textContent = r.raw;
  refresh();
}

setInterval(refresh, 2000);
refresh();
</script>
</body>
</html>
"""


class ConfigIn(BaseModel):
    mode: str | None = None
    t2_mode: str | None = None
    delay_seconds: float | None = None
    include_glue_a: bool | None = None
    t1_ip: str | None = None
    t2_ip: str | None = None
    t1_port: int | None = None
    t2_port: int | None = None


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return PAGE


@app.get("/api/state")
def state() -> dict:
    return {
        "now": time.time(),
        "domain": common.FQDN,
        "srv_owner": common.SRV_NAME,
        "targets": [common.TARGET1, common.TARGET2],
        "params": {
            "fetch_budget": common.FETCH_BUDGET,
            "srv_ttl": common.SRV_TTL,
            "glue_ttl": common.GLUE_TTL,
            "a_ttl": common.A_TTL,
        },
        "control": common.get_control(),
        "srv_cache": common.get_srv_cache(),
        "a_cache": common.get_a_cache(),
        "resolver_log": common.recent("query_log"),
        "auth_log": common.recent("auth_log"),
    }


@app.post("/api/config")
def set_config(cfg: ConfigIn):
    fields: dict = {}

    if cfg.mode is not None:
        if cfg.mode not in ("ok", "delay", "drop"):
            return JSONResponse({"ok": False,
                                 "error": f"unknown mode {cfg.mode!r}"}, 400)
        fields["mode"] = cfg.mode

    if cfg.t2_mode is not None:
        if cfg.t2_mode not in ("ok", "drop", "stale_version"):
            return JSONResponse({"ok": False,
                                 "error": f"unknown t2_mode {cfg.t2_mode!r}"}, 400)
        fields["t2_mode"] = cfg.t2_mode

    if cfg.delay_seconds is not None:
        if not (0 <= float(cfg.delay_seconds) <= 60):
            return JSONResponse({"ok": False,
                                 "error": "delay must be 0..60s"}, 400)
        fields["delay_seconds"] = float(cfg.delay_seconds)

    if cfg.include_glue_a is not None:
        fields["include_glue_a"] = 1 if cfg.include_glue_a else 0

    for key, val in (("t1_ip", cfg.t1_ip), ("t2_ip", cfg.t2_ip)):
        if val is not None:
            try:
                ipaddress.IPv4Address(val)
            except ValueError:
                return JSONResponse({"ok": False,
                                     "error": f"bad IPv4 address {val!r}"}, 400)
            fields[key] = val

    for key, val in (("t1_port", cfg.t1_port), ("t2_port", cfg.t2_port)):
        if val is not None:
            if not (1 <= int(val) <= 65535):
                return JSONResponse({"ok": False,
                                     "error": f"port {val} out of range"}, 400)
            fields[key] = int(val)

    if not fields:
        return JSONResponse({"ok": False, "error": "nothing to update"}, 400)
    return {"ok": True, "control": common.set_control(fields)}


def _fire(qname: str, qtype: str) -> dict:
    query = DNSRecord.question(qname, qtype)
    t0 = time.time()
    try:
        data = query.send(common.RESOLVER_HOST, common.RESOLVER_PORT,
                          timeout=common.FETCH_BUDGET + 6)
        rep = DNSRecord.parse(data)
    except Exception as exc:  # transport failure is reported, not raised
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}

    answers = []
    for rr in rep.rr:
        item = {"name": str(rr.rname), "type": QTYPE[rr.rtype],
                "ttl": rr.ttl}
        if rr.rtype == QTYPE.SRV:
            item.update(priority=int(rr.rdata.priority),
                        weight=int(rr.rdata.weight),
                        port=int(rr.rdata.port),
                        target=str(rr.rdata.target))
        else:
            item["data"] = str(rr.rdata)
        answers.append(item)

    txts = [str(rr.rdata).strip('"') for rr in rep.ar if rr.rtype == QTYPE.TXT]
    source = next(
        (t.split("=", 1)[1].split()[0] for t in txts if t.startswith("source=")),
        "unknown",
    )
    return {
        "ok": True,
        "rcode": RCODE[rep.header.rcode],
        "answers": answers,
        "source": source,
        "meta": txts,
        "elapsed_ms": int((time.time() - t0) * 1000),
        "raw": str(rep),
    }


@app.post("/api/query")
def do_query(qtype: str = "SRV") -> dict:
    """Fire a real DNS query at the resolver and report the actual reply."""
    qtype = qtype.upper()
    if qtype == "SRV":
        return _fire(common.SRV_NAME, "SRV")
    if qtype == "A":
        return _fire(common.FQDN, "A")
    return JSONResponse({"ok": False, "error": f"unsupported qtype {qtype!r}"}, 400)


def main() -> None:
    common.init_db()
    uvicorn.run(app, host="0.0.0.0", port=common.WEB_PORT, log_level="warning")


if __name__ == "__main__":
    main()
