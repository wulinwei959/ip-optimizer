# 域名清单 schema 与运行说明
核心只读一个文件：`domains.json`。没有 `settings.env`、没有 cron 定时任务。编辑保存后下一轮自动生效（每轮重新读取文件），也可 `POST /refresh` 即时刷新，无需重启服务。
**为什么是 JSON 而不是 YAML**：只用 Go 标准库 `encoding/json`。YAML 需要第三方模块，会引入 `go mod download`，与全离线构建、零依赖冲突。JSON 不支持注释，字段说明放在本文档。

## 字段

### 顶层

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `_readme` | string | 仅作提示，程序忽略 |
| `domains` | array | 仅探测的域名；**建议至少 1 个**，否则产物返回 503 |
| `defaults` | object | 全局默认值，可被单个域名覆盖 |

### `domains[]`

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 必填 | hosts 格式为**精确域名**不泛域名，不覆盖子域，需要哪些子域名就显式列出 |
| `sni` | string | = `name` | TLS 验证的 SNI / 验证主机名，用于辨别，节点开着但不加载该域名的错误 IP |
| `port` | int | 443 | 验证用的 TLS 端口 |
| `candidates` | string[] | 空 | 固定候选 IP 列表；不填则自动多源 DNS 解析并堕泛（自动去重、过滤 CGNAT、保留私网） |
| `allow_private` | bool | false | 是否允许解析结果中的 RFC1918 私网 IP |
| `expect_status` | int[] | 空（不校验） | **可选增强**：在 TLS 连接上校验 HTTP 状态码。默认不校验，因为绝大多数站点根路径返回 403/404 会误判 |
| `suppress_aaaa` | bool | true | 保留字段，仅在 `status.json` 中标记；**不生成任何产物**，见下文 IPv6 说明 |
| `expand` | bool | false | 是否启用域名展开（从主域名发现相关子域名） |
| `expand_sources` | string[] | 空（用全局默认） | 展开来源：`ct` (Certificate Transparency)、`wordlist` (常见子域名字典)、`rules` (内置服务规则) |
| `disabled` | bool | false | 禁用该域名：不参与探测，也不写入 `hosts.txt` / `agh.txt` / `status.json`；随时可改回 false 恢复 |

### `defaults`

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `schedule_minutes` | int | 60 | 轮询间隔，不依赖系统 crontab，1..1440 |
| `probe_dns` | string[] | 223.5.5.5 / 119.29.29.29 | 上游列表，可混用 UDP（**字面 IP**）、DoT（`tls://主机[:853]`）、DoH（`https://主机/路径`）；需绕开本机 AdGuard Home；不支持 DoQ |
| `probe_port` | int | 443 | 默认验证端口 |
| `concurrency` | int | 20 | 并发验证数 (1..256)，过高易被运营商网络拦截 |
| `hysteresis_percent` | int | 20 | 新 IP 需比当前优至少该百分比 |
| `hysteresis_rounds` | int | 2 | 连续多少轮达标才切换（防抖） |
| `max_candidates` | int | 64 | 单域名候选上限，防爆量 |
| `tcp_rounds` | int | 3 | TCP 探测次数，取中位数 |
| `timeout_seconds` | int | 3 | 单次 DNS / TCP / TLS 超时 |
| `probe_top_n` | int | 5 | 自适应探测面：常规轮次只测「当前 IP + 前 N 个挑战者」(1..64) |
| `probe_full_every` | int | 6 | 每 K 轮做一次全量候选扫描 (1..1000) |
| `watch_interval_seconds` | int | 60 | 健康探针间隔：只测当前生效 IP (5..3600) |
| `watch_switch_percent` | int | 100 | 当前 IP 相对自身上一轮时延变慢超过该百分比即触发即时轮次 (1..100) |
| `outputs` | string[] | 三项全开 | 保留字段，当前三项产物固定生成 |
| `expand_concurrency` | int | 10 | 域名展开并发数 (1..256) |
| `expand_timeout_seconds` | int | 10 | 域名展开单次超时 (1..60) |
| `expand_max_subdomains` | int | 50 | 域名展开最大子域名数 (1..1000) |
| `expand_sources` | string[] | ["wordlist", "rules"] | 全局默认展开来源 |
| `expand_cache_ttl_hours` | int | 12 | 子域扩展结果缓存 TTL (1..240 小时)；定时轮次复用，手动整轮刷新强制重新展开 |
| `history_retention_months` | int | 12 | 探测历史保留月数 (1..120)，过期分片自动清理 |
| `dns.listen` | string | `127.0.0.1:18053` | 内置 DNS 应答器监听地址 `host:port`（UDP 与 TCP 同端口）；空字符串禁用。填 `off` / `disabled` / `none` / `0` / `false` 也表示禁用。host 必须是 IP 字面量，留空表示监听全部接口 |
| `dns.ttl` | int | 60 | 应答给 A 记录的 TTL 秒数 (5..3600)，决定 IP 切换的收敛上限 |

`HO_SCHEDULE_MINUTES`、`HO_PROBE_DNS`、`HO_PROBE_CONCURRENCY`、`HO_PROBE_TOP_N`、`HO_PROBE_FULL_EVERY`、`HO_WATCH_INTERVAL_SECONDS`、`HO_WATCH_SWITCH_PERCENT`、`HO_EXPAND_CACHE_TTL_HOURS` 可覆盖 `defaults`；另有 `HO_DNS_LISTEN` 与 `HO_DNS_TTL` 可覆盖应答器配置（前者同样接受 off 类词表禁用）。`HO_PORT` / `HO_TZ` / `HO_CA_BUNDLE` / `HO_CONFIG` / `HO_LEGACY_CONFIG` / `HO_OUTPUT` / `HO_STATE` / `HO_DATA` / `HO_ADMIN_TOKEN` / `HO_UPDATE_CHECK` 见 `deploy/README.md` 与根 README。

## HTTP 端点（管理接口）

| 路径 | 说明 |
| --- | --- |
| `/` | 可读的观测首页 |
| `/hosts.txt` | `IP domain` 逐行，供 AdGuard Home、DNS 重写清单、/etc/hosts 订阅 |
| `/agh.txt` | `\|\|domain^$dnsrewrite=NOERROR;A;IP`，**推荐**：自动子域名且 AAAA 自动 NODATA |
| `/status.json` | 每个域名的选中 IP、通过数、生成 IP、换代原因、本轮时间 |
| `POST /refresh` | 提交后台刷新任务，立即返回 `202` + `task_id`；可选 JSON 体 `{"domains":["a.com"]}` 只刷新指定域名 |
| `GET /api/refresh-status?task_id=...` | 查询刷新进度：`running` / `done` / `error` |
| `GET /api/domains` | 读取 domains.json 原文 |
| `PUT/POST /api/domains` | 写入 domains.json（校验后原子写入） |
| `POST /api/expand` | 域名展开：`{ "domain": "github.com", "sources": ["wordlist", "rules"] }` |
| `GET /api/history` | 查询探测历史，支持 `domain`、`group`、`from`、`to`、`limit` |
| `POST /api/refresh-agh` | 只用当前快照重写 `agh.txt`，不触发探测 |
| `GET /api/candidates?domain=` | 返回该域名最近一轮全部候选 IP 与延迟、当前生效 IP |
| `POST /api/switch` | 手动切换当前 IP：`{"domain":"a.com","ip":"1.2.3.4"}` |
| `POST /api/disable` | 启用/禁用域名：`{"names":["a.com"],"disabled":true}` 或 `{"group":"github.com","disabled":true}`；禁用后立即从产物移除 |

文本端点返回 `ETag` / `Last-Modified`，支持 `If-None-Match` -> 304。  
无有效 IP 时 `hosts.txt` / `agh.txt` 返回 503（防止 AGH 订阅空清单），`status.json` 视为 200 并说明原因；配置校验、原子写保证关键时刻保留上一轮产物，不写坏文件。

## DNS 应答器：为什么比订阅更快

AdGuard Home 的过滤器订阅刷新间隔**最低只能设 1 小时**，而 `$dnsrewrite` 规则本身是静态替换，没有 TTL、没有健康度概念（见 `internal/filtering/dnsrewrite.go` 的 `processDNSRewrites`：只把应答记录换成你写的 IP）。因此走订阅链路时，即使本服务已经切到新 IP，客户端仍会在最长一个订阅周期内继续拿到旧 IP。

内置 DNS 应答器换了一条路：由 AGH 按域名分流、以普通上游的方式查询本服务。

```
探测 → 快照更新 → memory view 原子替换 → UDP 应答（TTL 由 dns.ttl 控制）
```

系统内唯一的时间常数从「AGH 刷新间隔 1h」变成「TTL（默认 60s）+ 探测周期」。

### 接入方式

在首页「DNS 应答服务」卡片复制分流规则，粘贴到 AGH 的「设置 → DNS 设置 → 上游 DNS 服务器」末尾，形如：

```
[/github.com/raw.githubusercontent.com/]127.0.0.1:18053

```

方括号内是**启用域名的完整名**（不是注册域），因为 `||domain^` 会匹配该域名及其全部子域；若只列注册域，已独立配置的子域会被父域规则劫持，永远拿不到自己的优选 IP。

该模式与「过滤器订阅」**二选一**，不要同时启用。

### 应答语义

| 查询 | 应答 |
| --- | --- |
| A，命中且有生效 IP | `NOERROR` + 1 条 A，TTL 取 `dns.ttl` |
| AAAA，命中 | `NOERROR` + 0 条（NODATA），与 `agh.txt` 的 AAAA 抑制一致 |
| 其他类型，命中 | `NOERROR` + 0 条（只承诺 A/AAAA） |
| 命中但该域名本轮无可用 IP | `REFUSED`（宁可解析失败，不返回旧 IP） |
| 清单外域名 | `REFUSED` + 限频日志（暴露 AGH 分流清单与 `domains.json` 不同步） |
| `QDCOUNT` 非法 / name 越界 / label 超长 | `FORMERR`（QDCOUNT 置 0）或静默丢弃 |
| 报文短于 12 字节 | 静默丢弃并计入 `malformed` |
| `QCLASS` 非 IN / 非查询包 | `REFUSED` / 静默丢弃 |

域名匹配与 AGH 的 `||domain^` 对齐：先精确匹配，未命中则逐级去掉最左侧标签向上找父域规则（`a.b.c` → `b.c` → `c`），**不做后缀通配**。

### 运行状态

`GET /api/dns` 返回 `enabled` / `listen` / `addr` / `ttl` / `queries` / `answered` / `nodata` / `refused` / `malformed` / `last_query_at` / `agh_upstream`。首页同名卡片每 5 秒刷新一次并展示同样的计数。

### 安全

默认只监听 `127.0.0.1`，与 AGH 同机部署时最安全。若改为 `0.0.0.0` 对外监听，必须自行添加防火墙规则：应答器**无鉴权**，任何能访问该端口的人都能让这些域名指向你选的 IP。

### 重启恢复

启动时先从 `status.json` 恢复应答视图，再读 `hosts.txt` / `agh.txt`。因此即使产物文件缺失，重启后应答器也能立即服务，不会出现「重启后到首轮探测完成前分流域名全部 REFUSED」的真空期。

## 关于 IPv6：一个已验证的坑

`||domain^$dnsrewrite=NOERROR;AAAA;` **不是合法规则**，AdGuard 的 urlfilter 源码（`rules/dnsrewrite.go` 的 `dnsRewriteRRHandlers[dns.TypeAAAA]`）要求 VALUE 必须是合法 IPv6 地址，否则会被判为非法；`loadDNSRewriteNormal` 仅在 `rrStr` 与 `valStr` **均为空** 时返回空 RCODE 通过，而这不区分记录类型。  
而官方 wiki 说明：`dnsrewrite` 规则会劫持该域名**整个 DNS 服务**，应包含与查询类型匹配的所有记录。  
因此 **AAAA 查询会返回空 NOERROR（NODATA）**，`agh.txt` 自然屏蔽 IPv6 泄露，无需额外 `suppress_aaaa`。  
这也是推荐优先用 `agh.txt` 而非 `hosts.txt` 的核心原因之一：`hosts.txt` 由 `/etc/hosts` 解析，AAAA 可能被错误解析。

## 手动编辑域名清单

1. **共享目录（1.4.0 起，推荐）**：文件管理器「应用文件」→ hosts-optimizer → data → `domains.json`，可直接查看/编辑/备份；保存后 `POST /refresh` 即时生效。旧位置 `@appconf` 的配置在升级后启动时自动一次性迁移到这里。
2. **SSH 编辑**：共享目录实际路径 `/vol1/@appshare/hosts-optimizer/data/domains.json`（`TRIM_DATA_SHARE_PATHS` 首段），保存后 `POST /refresh` 即时生效
3. **Web 编辑页面**：管理界面与订阅端点共用同一 HTTP 服务；「编辑域名清单」默认是图形化表单，可直接修改轮询周期、DNS、并发、超时、滞回与子域名展开参数，也可增删域名或打开单域名高级项；需要时切到 JSON 源码。上方域名发现工具支持输入主域名后勾选批量添加，状态表按主域名分组并支持整组勾选/批量删除

   DNS 应答器的 `defaults.dns.listen` / `defaults.dns.ttl`、`defaults.expect_status`、`defaults.outputs` 以及域名级的 `expect_status` / `allow_private` / `suppress_aaaa` 都可在表单内直接填写；数值字段已带范围校验，off 类词表（`off` / `disabled` / `none` / `0` / `false`）可直接填在监听地址里禁用应答器。

## 本地启动
```bash
cd core
mkdir -p /tmp/ho-config && cp ../deploy/config-schema/domains.example.json /tmp/ho-config/domains.json
HO_CONFIG=/tmp/ho-config HO_OUTPUT=/tmp/ho-out HO_STATE=/tmp/ho-state HO_PORT=18088 \
  go run ./cmd/hosts-optimizer
```

`HO_CONFIG` 指向**目录**，目录内必须有 `domains.json`。`go run ./cmd/hosts-optimizer -check-config` 可仅校验配置不启动服务。
