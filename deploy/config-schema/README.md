# 域名清单 schema 与运行说明

核心只读一个文件：`domains.json`。不再有 `settings.env`、不再有 cron 表达式。**编辑后下一轮自动生效**（每轮重新读取文件），也可 `POST /refresh` 立即重跑，无需重启服务。

**为什么是 JSON 而不是 YAML**：核心用 Go 标准库 `encoding/json`。YAML 需要第三方模块，会引入 `go mod download`，与「构建全程离线」冲突。JSON 不支持注释，字段说明放在本文档。

## 字段

### 顶层

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `_readme` | string | 仅作提示，核心忽略 |
| `domains` | array | 待优选域名；**建议至少 1 条**，否则订阅端点返回 503 |
| `defaults` | object | 全局默认值，可被单个域名覆盖 |

### `domains[]`

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `name` | string | 必填 | hosts 语法是**精确匹配**、不覆盖子域，需要哪些子域就逐条列 |
| `sni` | string | = `name` | TLS 校验的 SNI / 证书主机名，用于淘汰「端口开着但不承载该域名」的错误 IP |
| `port` | int | 443 | 探测与 TLS 校验端口 |
| `candidates` | string[] | 空 | 固定候选 IP 池；不填则走多源 DNS 采集并集（自动过滤回环、私有、CGNAT、保留段） |
| `allow_private` | bool | false | 是否允许采集结果中的 RFC1918 私有 IP |
| `expect_status` | int[] | 空（不校验） | **可选增强**：在 TLS 连接上校验 HTTP 状态码。默认关闭，因为部分站点对根路径返回 403/404 会误杀 |
| `suppress_aaaa` | bool | true | 保留兼容字段，仅在 `status.json` 中标记；**不生成额外规则**，原因见下 |

### `defaults`

| 字段 | 类型 | 默认 | 说明 |
| --- | --- | --- | --- |
| `schedule_minutes` | int | 60 | 进程内定时，不依赖宿主 crontab（1..1440） |
| `probe_dns` | string[] | 223.5.5.5 / 119.29.29.29 | 必须是**字面 IP**；必须绕开本机 AdGuard Home |
| `probe_port` | int | 443 | 默认探测端口 |
| `concurrency` | int | 20 | 并发探测数（1..256），过高易被视作网络扫描 |
| `hysteresis_percent` | int | 20 | 新 IP 需比当前快至少该百分比 |
| `hysteresis_rounds` | int | 2 | 且需连续胜出该轮数才切换（防抖） |
| `max_candidates` | int | 64 | 单域名候选上限，防扫描量失控 |
| `tcp_rounds` | int | 3 | TCP 握手测速次数，取中位数 |
| `timeout_seconds` | int | 3 | 单次 DNS / TCP / TLS 超时 |
| `outputs` | string[] | 三件套 | 保留字段；当前三份产物始终生成 |

`HO_SCHEDULE_MINUTES`、`HO_PROBE_DNS`、`HO_PROBE_CONCURRENCY` 可覆盖 `defaults`；`HO_PORT` / `HO_TZ` / `HO_CA_BUNDLE` / `HO_CONFIG` / `HO_OUTPUT` / `HO_STATE` 见 `deploy/README.md`。

## HTTP 端点（单端口）

| 路径 | 说明 |
| --- | --- |
| `/` | 人类可读概览页 |
| `/hosts.txt` | `IP domain` 逐行，供 AdGuard Home「DNS 封锁清单」订阅 |
| `/agh.txt` | `\|\|domain^$dnsrewrite=NOERROR;A;IP`，**推荐**：覆盖子域且 AAAA 自动 NODATA |
| `/status.json` | 每域名的候选数、通过数、生效 IP、延迟、切换原因、本轮时间 |
| `POST /refresh` | 立即重跑一轮 |

文本端点返回 `ETag` / `Last-Modified`，支持 `If-None-Match` → 304。**无任何生效 IP 时** `hosts.txt` / `agh.txt` 返回 503（避免 AGH 接受空列表），`status.json` 仍为 200 并说明原因；整轮校验全灭时**保留上一轮产物**，绝不写空文件。

## 关于 IPv6：一个已查证的坑

`||domain^$dnsrewrite=NOERROR;AAAA;` **不是合法规则**。AdGuard 的 urlfilter 源码（`rules/dnsrewrite.go` 的 `dnsRewriteRRHandlers[dns.TypeAAAA]`）要求 VALUE 必须是合法 IPv6 地址，空值会被判为非法；`loadDNSRewriteNormal` 只在 `rrStr` 与 `valStr` **都为空**时才返回纯 RCODE 重写，而那种写法不区分记录类型。

而官方 wiki 明确：`dnsrewrite` 规则会替换该域名整个 DNS 应答，应答中只包含与查询类型匹配的记录 —— 因此 **AAAA 查询会返回空 NOERROR（NODATA）**，`agh.txt` 天然避免 IPv6 绕过，无需额外规则。所以实现里不输出任何 AAAA 规则，示例配置也不再带 `suppress_aaaa`。

反过来，若订阅的是 `hosts.txt`（`/etc/hosts` 语法、精确匹配），AAAA 仍可能走正常解析 —— 这是推荐优先使用 `agh.txt` 的原因之一。

## 手动编辑域名清单

1. **SSH 编辑**（当前最稳）：`/var/apps/hosts-optimizer-native/etc/domains.json`，保存后 `POST /refresh` 立即生效
2. **共享目录**：在 `config/resource` 加 `data-share`，让用户在飞牛文件管理器里直接编辑；需真机验证 `TRIM_DATA_SHARE_PATHS` 注入时序，当前骨架未启用
3. **Web 编辑页**：二期；单端口约束下管理页必须与订阅端点合并到同一 HTTP 服务

## 本地开发运行

```bash
cd core
mkdir -p /tmp/ho-config && cp ../deploy/config-schema/domains.example.json /tmp/ho-config/domains.json
HO_CONFIG=/tmp/ho-config HO_OUTPUT=/tmp/ho-out HO_STATE=/tmp/ho-state HO_PORT=18088 \
  go run ./cmd/hosts-optimizer
```

`HO_CONFIG` 指向**目录**，目录内必须有 `domains.json`。`go run ./cmd/hosts-optimizer -check-config` 可只校验配置不启动服务。
