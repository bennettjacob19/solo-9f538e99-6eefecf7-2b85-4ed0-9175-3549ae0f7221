# DNS SRV 整组原子解析系统

LDAP 客户端查询 `_ldap._tcp.service.example` 的 SRV 记录时，本地权威端在
**一次 UDP 答复**里给齐主备两个目标（优先级、端口）以及它们的附加 A。解析器把
这组记录当作一个**不可分割的整体**解析、校验、缓存与重查。

## 组成

| 服务 | 模块 | 端口 | 说明 |
|---|---|---|---|
| `auth` | `app.auth_server` | UDP 5354 | 本地权威端，行为由网页实时切换 |
| `resolver` | `app.resolver` | UDP 5353 | 整组原子缓存解析器（对外发布） |
| `web` | `app.web` | HTTP 8000 | FastAPI 操作网页 |

三者通过共享卷上的 SQLite（WAL 模式）协作：`control` 表存权威端行为与
**配置版本号**，`srv_cache` 存整组缓存（**绝对时间戳**），`a_cache` 存普通 A
缓存，`query_log`/`auth_log` 供网页展示。

## 运行

```bash
docker compose up --build
# 网页:  http://localhost:8000
# SRV:   dig @127.0.0.1 -p 5353 _ldap._tcp.service.example SRV
# A:     dig @127.0.0.1 -p 5353 service.example A
```

无 Docker 的本地运行（等价三进程）：

```bash
pip install -r requirements.txt
DB_PATH=/tmp/dns/app.db AUTH_PORT=15354 python -m app.auth_server &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 AUTH_PORT=15354 python -m app.resolver &
DB_PATH=/tmp/dns/app.db RESOLVER_PORT=15353 WEB_PORT=8000 python -m app.web &
```

自测（自动拉起三进程，跑全部关键交错，约 20 秒）：

```bash
python tests/selftest.py
```

## 解析语义

### 1. 一次答复给齐主备目标与附加 A

权威端对 SRV 查询返回两条 SRV（`priority 10` 主、`priority 20` 备，各自端口与
目标名），默认在附加段给出两个目标的 A。每条上游答复的附加段还带一条内部
TXT（`_cfgver.<domain> TXT "v=<版本>"`），该 TXT **不会**透出给客户端。

### 2. 网页可改两台目标的 IPv4 与端口，可省略附加 A

网页可分别编辑 `ldap1`/`ldap2` 的 IPv4 和端口，并可取消"附带附加 A"。每次保存
都会让配置版本号 `version` 原子 +1。省略附加 A 后，解析器必须自行补查两个目标
的 A 才能凑齐整组结果。

### 3. 共享 2 秒预算 + 并发补查 + 重试

从**首次回源 SRV 查询**起建立一个统一的单调钟截止时刻（`FETCH_BUDGET`=2s）。
之后：

- 缺失目标的 A 由线程池**并发**补查；
- 每次查询都用**独立 socket + 随机事务 ID + 问题匹配**，失败就在剩余预算内
  **重试**（新 socket、新事务 ID）；
- 所有补查和所有重试共用这同一个 2 秒预算，绝不为单个子查询单独再开 2 秒；
- 迟到的旧答复落到已关闭的 socket，且事务 ID/问题不匹配，无法被错配或复活。

### 4. 只有同版完整结果才能答复和写缓存

- 解析器只接受带版本号 TXT 的上游记录；SRV 与每个 A 的版本号必须**完全一致**。
- 配置在解析途中变更会产生混版结果：混版记录一律丢弃，在剩余预算内重试。
- 必须同时拿到 **2 条 SRV + 每个目标各 1 条 A** 且版本相同，才允许答复客户端，
  并原子写入 `srv_cache`。失败的轮次**绝不**写缓存，也**绝不**返回残缺记录。

### 5. 最早到期记录决定整组期限，并限制每条答复 TTL

- 权威侧 SRV TTL（默认 10s）与附加 A TTL（默认 5s）刻意不同。
- 整组缓存期限 = 组内**最早到期**那条记录的到期时刻（这里是 5s 的 A）。
- 缓存命中时，每条 RR 的答复 TTL 都被压到**整组剩余期限**（即 SRV 也不会超过
  剩余的 A 寿命），TTL 随时间倒数。
- 期限以绝对 epoch 持久化在 SQLite，**重启不重新计时**。

### 6. 到期整组重查

整组一旦到期，下一次查询触发**整组**重新回源（不是只补过期的那一条）。并发的
缓存缺失请求由单飞（single-flight）合并为同一轮回源，避免惊群。

### 7. 时限内收不齐同版结果 → 空的 SERVFAIL

若 2 秒内无法凑齐同版完整结果（权威端丢包、延迟超预算、补查目标失联、版本始终
交错等），返回 **SERVFAIL，且应答段不含任何 SRV 或 A**，也不写缓存。

### 8. 普通 A 查询照常

`service.example` 的 A 查询走独立的 `a_cache` 与独立回源路径，不受 SRV 整组
成败影响。解析器只服务本域：域外名称 REFUSED，SRV 名称的非 SRV 查询 NODATA。

## 网页与故障注入

网页可切换整端故障模式，并可对目标 2 的 A 补查单独注入：

- 整端：`ok` 正常 / `delay` 延迟应答（默认 3s，大于 2s 预算）/ `drop` 不应答；
- 目标 2 单独：`ok` / `drop`（补查丢包）/ `stale_version`（永远回上一版版本号，
  确定性地制造混版，用于演练同版校验）。

网页"发起查询"经解析器发**真实 DNS 报文**，展示实际 rcode、每条答复（SRV 的
优先级/端口/目标、A 地址）、逐记录 TTL、来源（`upstream` / `cache-fresh` /
`none`，由解析器在附加段 TXT `_src.<域名>` 带回），以及双方日志。

## 文件

```
app/common.py       配置 + SQLite 状态面（control / srv_cache / a_cache / 日志）
app/auth_server.py  可控权威端：SRV+附加 A、目标 A、版本 TXT、故障注入
app/resolver.py     整组原子解析器：共享预算、并发补查、同版校验、整组缓存
app/web.py          FastAPI 操作网页
tests/selftest.py   端到端自测（A–G 七组场景，41 项断言）
Dockerfile / docker-compose.yml / requirements.txt
```

## 可调环境变量

| 变量 | 默认 | 含义 |
|---|---|---|
| `FETCH_BUDGET` | 2.0 | 整轮回源共享预算（秒），补查与重试共用 |
| `SRV_TTL` | 10 | 权威 SRV 记录 TTL |
| `GLUE_TTL` | 5 | 权威附加/目标 A TTL（最早到期，决定整组期限） |
| `A_TTL` | 5 | 普通 `service.example` A 的 TTL |
| `FIXED_DOMAIN` | service.example | 固定域 |
