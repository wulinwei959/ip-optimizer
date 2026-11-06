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
| `outputs` | string[] | 三项全开 | 保留字段，当前三项产物固定生成 |
| `expand_concurrency` | int | 10 | 域名展开并发数 (1..256) |
| `expand_timeout_seconds` | int | 10 | 域名展开单次超时 (1..60) |
| `expand_max_subdomains` | int | 50 | 域名展开最大子域名数 (1..1000) |
| `expand_sources` | string[] | ["wordlist", "rules"] | 全局默认展开来源 |
| `history_retention_months` | int | 12 | 探测历史保留月数 (1..120)，过期分片自动清理 |

`HO_SCHEDULE_MINUTES`、`HO_PROBE_DNS`、`HO_PROBE_CONCURRENCY` 可覆盖 `defaults`；`HO_PORT` / `HO_TZ` / `HO_CA_BUNDLE` / `HO_CONFIG` / `HO_OUTPUT` / `HO_STATE` 见 `deploy/README.md`。

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

文本端点返回 `ETag` / `Last-Modified`，支持 `If-None-Match` -> 304。  
无有效 IP 时 `hosts.txt` / `agh.txt` 返回 503（防止 AGH 订阅空清单），`status.json` 视为 200 并说明原因；配置校验、原子写保证关键时刻保留上一轮产物，不写坏文件。

## 关于 IPv6：一个已验证的坑

`||domain^$dnsrewrite=NOERROR;AAAA;` **不是合法规则**，AdGuard 的 urlfilter 源码（`rules/dnsrewrite.go` 的 `dnsRewriteRRHandlers[dns.TypeAAAA]`）要求 VALUE 必须是合法 IPv6 地址，否则会被判为非法；`loadDNSRewriteNormal` 仅在 `rrStr` 与 `valStr` **均为空** 时返回空 RCODE 通过，而这不区分记录类型。  
而官方 wiki 说明：`dnsrewrite` 规则会劫持该域名**整个 DNS 服务**，应包含与查询类型匹配的所有记录。  
因此 **AAAA 查询会返回空 NOERROR（NODATA）**，`agh.txt` 自然屏蔽 IPv6 泄露，无需额外 `suppress_aaaa`。  
这也是推荐优先用 `agh.txt` 而非 `hosts.txt` 的核心原因之一：`hosts.txt` 由 `/etc/hosts` 解析，AAAA 可能被错误解析。

## 手动编辑域名清单

1. **SSH 编辑**（目前最稳）：`/var/apps/hosts-optimizer-native/etc/domains.json`，保存后 `POST /refresh` 即时生效
2. **共享目录**：在 `config/resource` 加 `data-share`，让用户在群晖文件管理器中编辑；需验证 `TRIM_DATA_SHARE_PATHS` 挂载目录，目前未启用
3. **Web 编辑页面**：管理界面与订阅端点共用同一 HTTP 服务；「编辑域名清单」默认是图形化表单，可直接修改轮询周期、DNS、并发、超时、滞回与子域名展开参数，也可增删域名或打开单域名高级项；需要时切到 JSON 源码。上方域名发现工具支持输入主域名后勾选批量添加，状态表按主域名分组并支持整组勾选/批量删除

## 本地启动
```bash
cd core
mkdir -p /tmp/ho-config && cp ../deploy/config-schema/domains.example.json /tmp/ho-config/domains.json
HO_CONFIG=/tmp/ho-config HO_OUTPUT=/tmp/ho-out HO_STATE=/tmp/ho-state HO_PORT=18088 \
  go run ./cmd/hosts-optimizer
```

`HO_CONFIG` 指向**目录**，目录内必须有 `domains.json`。`go run ./cmd/hosts-optimizer -check-config` 可仅校验配置不启动服务。
