# 技术文档

> 适用版本：1.5.0 · 更新：2026-11-12
>
> 本文描述内部实现与数据契约；配置字段与部署步骤见 [`deploy/config-schema/README.md`](../deploy/config-schema/README.md) 与 [`deploy/README.md`](../deploy/README.md)。

> 1.2.0 起新增管理令牌鉴权、健康探针（watchdog）与自适应探测面；1.3.0 起令牌/日志落到用户可见共享目录（`HO_DATA`）；1.4.0 起新增子域扩展缓存、DNS 应答器 TCP、`domains.json` 迁移共享目录、`/refresh` 限流与 GitHub 新版本检查（`internal/update`）。1.5.0 起轮次锁改为带超时信号量（`internal/app/roundlock.go`）、整轮 deadline 超时作废、扩展缓存/探针状态/快照周期裁剪，`/healthz` 增加轮次耗时/超时计数/锁占用/缓存与状态规模观测字段；接入方式改为「DNS 应答器 / AGH 订阅」下拉二选一，管理令牌与检查更新移入「设置与关于」面板；移除 `suppress_aaaa` / `outputs` 配置项（旧键自动忽略）。

## 1. 架构总览

```
浏览器 / AdGuard Home
        │  HTTP（单端口，默认 18088）
        ▼
  app（net/http）
  ├─ 首页（html/template，无前端构建）
  ├─ 订阅端点 /hosts.txt /agh.txt /status.json
  ├─ 管理 API（配置、展开、刷新、历史、候选、切换、日志）
  └─ 异步刷新任务（task_id + 轮询）
        │
        ▼
  doRound / doRoundFor
  config → dnsquery → probe → store.Decide
        │
        ├─ output.Build → 三份产物（原子写）
        ├─ history → 按月 gzip JSONL
        └─ logbuf → 内存环形日志（2000 行）
```

同一进程内还有一条为「IP 切换即时生效」而设的通道：

```
 快照更新（轮末 / 手动切换 / 禁用 / 恢复）
   │
   ▼
 applyDNSSnapshot → dnsserver.NewView → atomic.Pointer 原子替换
   │
   ▼
 UDP/TCP DNS 应答器（默认 127.0.0.1:18053，TTL 默认 60s）
   ▲
   └── AdGuard Home 按域名分流直连：[/github.com/...]127.0.0.1:18053
 ```

核心只使用 Go 标准库，`CGO_ENABLED=0` 交叉编译为单个静态 ELF；构建脚本强制 `GOPROXY=off`，不引入任何第三方模块。

## 2. 包结构

| 包 | 职责 |
| --- | --- |
| `cmd/hosts-optimizer` | 入口：`-version` / `-check-config` / 服务启动；把日志同时写入 stdout 与内存缓冲 |
| `internal/config` | 读取并校验 `domains.json`，合并 `HO_*` 环境变量，解析域名级覆盖 |
| `internal/dnsquery` | 手写 DNS 报文；支持 UDP、DoT（`tls://`）、DoH（`https://`）；DoQ 明确不支持 |
| `internal/probe` | TCP 握手测速（多轮取中位数）+ TLS/SNI 证书链校验 |
| `internal/store` | 持久化每域名状态与最近候选列表；实现滞回与失败不覆盖 |
| `internal/output` | 生成 `hosts.txt` / `agh.txt` / `status.json` 与 ETag |
| `internal/history` | 追加式历史存储：按月 gzip 分片、保留期清理、范围查询；`Store` 接口便于将来换 SQLite |
| `internal/logbuf` | 线程安全环形日志缓冲，供 `/api/logs` 增量读取 |
| `internal/logfile` | 日志落盘 Writer：追加写 + 8MB 轮转保留一份备份（1.3.0，写入 `HO_DATA/logs/app.log`） |
| `internal/expand` | 子域名发现：CT 日志、字典、内置规则 |
| `internal/dnsserver` | 内置 UDP/TCP DNS 应答器：极简报文解析、`View` 父域回退匹配、原子视图替换，供 AGH 上游分流 |
| `internal/update` | GitHub 新版本检查：语义化版本比较、`releases/latest` 异步查询、小时级复检（1.4.0） |
| `internal/app` | HTTP 路由、探测编排、异步任务、快照管理、管理 API、扩展缓存、watchdog、轮次锁（`roundlock.go`，1.5.0） |

## 3. 一轮探测

1. `config.Load()` 重新读取 `domains.json`（热加载，无需重启）；主路径缺失而 `HO_LEGACY_CONFIG` 有旧文件时一次性迁移（见第 5 节）。
2. 解析目标：显式域名优先，随后对 `expand=true` 的域名做子域名发现（仅全量轮次）。**扩展结果带 TTL 缓存**（`expand_cache_ttl_hours`，默认 12h）：定时轮次命中缓存直接复用；手动整轮 `/refresh` 强制重新展开；展开参数（来源/并发/上限/探测 DNS）变化会使缓存指纹失效。命中/未命中计数见 `/healthz`。
3. 候选采集：`dnsquery.CollectWithOptions` 并发查询所有上游，过滤回环/私有/CGNAT/保留段。
4. 探测校验：TCP 握手多轮取中位数，再做 TLS 握手与证书链校验（`InsecureSkipVerify=false`）。**自适应探测面**：常规轮次只测「当前 IP + 前 `probe_top_n` 个挑战者」，每 `probe_full_every` 轮做一次全量扫描。
5. 决策：`store.Decide` 应用滞回（默认新 IP 需快 ≥20% 且连续 2 轮胜出）。
6. 落盘：`output.Build` 生成三份产物，`util.AtomicWrite` 以「临时文件 → Sync → Rename」写入。
7. 历史：每域名一行写入当月 `history/rounds-YYYYMM.jsonl.gz`。
8. 快照：在 `a.mu` 保护下替换内存快照，订阅端点立即读到新内容。

**轮次锁与超时治理（1.5.0）**：所有会改产物/状态的操作统一经 `roundMu`（`roundlock.go`，带超时的信号量式互斥）串行化。六处加锁入口按语义差异化等待：轮次入口等到当前轮结束，写配置与切换入口等短、拿不到锁即快速失败（409）；整轮 deadline 取 `max(scheduleMinutes, 2)` 与 15 分钟的最小值，超时作废本轮（保留上一轮产物），避免慢网络或挂死把后续轮次全部堵死。锁占用与超时作废计数见 `/healthz`。

**健康探针（watchdog）**：独立 goroutine 每 `watch_interval_seconds` 只测各域名「当前生效 IP」，失效或相对自身上一轮时延变慢超过 `watch_switch_percent` 时触发一次定向即时轮次（带指数退避），把故障发现延迟从整轮周期降到分钟级。定向轮次不展开子域名。

### 全量与定向刷新

- `POST /refresh`（无 body）执行全量轮次，**强制重新展开子域名**（绕过 TTL 缓存）。
- `POST /refresh {"domains":["a.com"]}` 只探测指定域名：不做子域名发现，结果通过 `mergeEntries` 合并回现有快照，其余域名保持不变。
- **限流**：距上次手动刷新不足 10 秒返回 `429`；已有任务在跑时直接复用（不受限流影响）；watchdog 走 `doRoundFor` 不经过此限流。
- 行内「刷新」与「刷新选中」都走定向刷新。
- 手动切换 IP 不重新探测，直接用最近候选列表更新状态与产物。

## 4. 决策与失败保护

- **首次采用**：无历史时选择本轮最快且通过校验的 IP。
- **保持当前最优**：当前 IP 仍是本轮最快时保持。
- **立即切换**：当前 IP 未通过 TLS 校验时立即切换。
- **滞回切换**：新 IP 需快至少 `hysteresis_percent`，并连续 `hysteresis_rounds` 轮胜出。
- **失败不覆盖**：本轮无任何可用 IP 时保留上一轮产物；首次启动且从未成功时才写仅含注释的文件。

## 5. 数据与存储

### 运行时目录（fnOS）

| 路径 | 内容 |
| --- | --- |
| `/vol1/@appshare/hosts-optimizer/data/domains.json` | 配置（1.4.0 起，用户可见共享目录） |
| `/vol1/@appshare/hosts-optimizer/data/admin-token` | 管理令牌（1.3.0 起，持久化、重启复用，0600） |
| `/vol1/@appshare/hosts-optimizer/data/logs/app.log` | 运行日志（8MB 轮转保留一份备份） |
| `/vol1/@appconf/hosts-optimizer-native/domains.json` | 旧配置位置（1.4.0 前）；启动时若主路径缺失则一次性迁移到共享目录 |
| `/vol1/@appdata/hosts-optimizer-native/output/` | `hosts.txt` / `agh.txt` / `status.json` |
| `/vol1/@appdata/hosts-optimizer-native/state/state.json` | 每域名当前 IP、滞回状态、最近候选列表 |
| `/vol1/@appdata/hosts-optimizer-native/state/history/` | `rounds-YYYYMM.jsonl.gz` 历史分片 |

**配置迁移（1.4.0）**：`service-setup` 注入 `HO_CONFIG=${DATA_DIR}`（共享目录根）与 `HO_LEGACY_CONFIG=${TRIM_PKGETC}`（旧目录）。`config.Load` 发现主路径无 `domains.json` 而旧路径有时，读取旧文件、原子写回主路径、删除旧文件（完成移动）并记日志；迁移一次性、幂等，本轮继续使用旧文件内容。`/api/domains` 返回的 `path` 自动指向新位置。`install_callback` 仍在旧位置播种默认清单作为兼容回退。

**共享目录（1.3.0）**：`config/resource` 声明 `data-share`（`hosts-optimizer/data`），文件管理器「应用文件」可见。`service-setup` 从 `TRIM_DATA_SHARE_PATHS` 首段取 `DATA_DIR` 并注入 `HO_DATA`；令牌与日志据此落盘，普通用户可直接查看/备份。

### `state.json` 关键字段

```json
{
  "domains": {
    "github.com": {
      "ip": "20.205.243.166",
      "latency_ms": 1.1,
      "last_check": "2026-11-07T01:08:48+08:00",
      "last_switch": "2026-11-07T01:08:48+08:00",
      "validated_last_round": 1,
      "candidates": [
        { "ip": "20.205.243.166", "latency_ms": 1.1 }
      ]
    }
  }
}
```

### 历史记录

每行一条 JSON，字段：`time`、`round_id`、`domain`、`group`、`ip`、`latency_ms`、`candidates`、`validated`、`reason`。按月分片、gzip 压缩，默认保留 12 个月（`history_retention_months`）。

### 禁用语义

- `domains[].disabled=true` 的域名不参与任何探测轮次，也不写入 `hosts.txt` / `agh.txt` / `status.json`。
- 通过 `/api/disable` 禁用时立即从当前快照与产物中移除；启用后标记为「待探测」，下一轮或手动刷新恢复。
- 保存配置时同样会移除已禁用域名，避免「页面已禁用但订阅仍生效」。

## 6. HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/` | 管理页面 |
| GET | `/hosts.txt` / `/agh.txt` / `/status.json` | 订阅与状态（ETag / 304） |
| POST | `/refresh` | 异步刷新；可选 `{"domains":[...]}` 定向刷新；返回 202 + `task_id` |
| GET | `/api/refresh-status` | 查询刷新任务状态 |
| POST | `/api/refresh-agh` | 仅用当前快照重写 `agh.txt`，不探测 |
| GET | `/api/domains` / PUT | 读取/校验并写回配置 |
| POST | `/api/expand` | 子域名发现（不修改配置） |
| GET | `/api/history` | 历史查询（domain/group/from/to/limit） |
| GET | `/api/candidates` | 最近一轮候选 IP 与延迟 |
| POST | `/api/switch` | 手动切换候选 IP 并立即生效 |
| POST | `/api/disable` | 启用/禁用域名（按 names 或 group），禁用后立即从产物移除 |
| GET | `/api/logs` | 增量读取运行日志 |
| GET | `/healthz` | 健康探针：版本、运行时长、`data_dir`、扩展缓存命中/未命中、轮次耗时/超时计数/锁占用、探针与状态规模、`update_available` / `latest_version`、watchdog 统计（公开，无需令牌） |
| POST | `/api/update-check` | 手动检查 GitHub 新版本（60 秒限流），返回 `latest_version` / `update_available` |

**鉴权（1.2.0 起）**：管理端点（`/api/*`、`/refresh`）需令牌，经 `X-Admin-Token` 头、`Authorization: Bearer` 或 `?token=` 传递，常量时间比较。令牌优先级：`HO_ADMIN_TOKEN` 环境变量 > 共享目录 `admin-token` 文件 > 启动时生成并持久化。订阅端点（`/hosts.txt`、`/agh.txt`、`/status.json`、`/healthz`）与首页无需令牌。写接口仍要求 `Content-Type: application/json`（阻止简单跨站表单）。服务默认监听所有网卡，只应部署在内网。

**新版本检查（1.4.0）**：`internal/update.Checker` 启动后异步查 `api.github.com/repos/wulinwei959/ip-optimizer/releases/latest`（10s 超时，失败静默），随后每小时复检；`Compare` 做三段语义化版本比较（容忍 `v` 前缀）。`/healthz` 暴露 `update_available` / `latest_version` / `update_checked_at`，页头据此显示「发现新版本 X」徽标。`HO_UPDATE_CHECK=off` 关闭。

## 7. 并发与一致性

| 锁 | 保护对象 | 说明 |
| --- | --- | --- |
| `roundMu` | 探测轮次、手动切换、AGH 重建 | 带超时的信号量式互斥（`roundlock.go`，1.5.0）；串行化所有会改产物/状态的操作，六入口差异化等待，整轮 deadline 超时作废 |
| `refreshMu` | `refreshTask`、`lastRefresh` | 异步任务状态与限流；已有任务时复用 |
| `stateMu` | `store.State` | 每域名决策与候选列表读写 |
| `mu` | `snap` 快照 | 订阅端点读、轮次结束替换 |
| `expandCacheMu` | `expandCache` | 子域扩展结果缓存；命中/未命中计数用 atomic |
| `watchMu` | `watchStates` 等 | watchdog 退避与最近检查/触发记录 |
| `update.Checker.mu` | 最新版本缓存 | 新版本检查状态读写 |

产物只通过 `AtomicWrite` 更新，读端不会看到半截文件。

## 8. 前端

- 单个 `html/template` 字符串，无打包步骤、无外部 CDN。
- 状态表按可注册主域名分组，支持展开/收起、整组勾选、批量刷新/删除。分组展开状态存放在浏览器 `localStorage` 的 `ho-group-open` 键（`{主域名: bool}`），只有点击分组标题与「全部展开/收起」会写入；禁用域名、禁用本组、勾选、切换 IP、保存配置或刷新完成后触发页面重载时据此恢复，不会被自动收起。搜索命中时的展开是临时的（不写入存储），清空关键词后只还原这些临时展开的分组。
- 表格会合并「配置中的域名」与「本轮状态」：尚未探测的域名以「待探测」行展示，保存后即可看到并直接刷新。
- 延迟单元格可打开候选 IP 弹窗并手动切换。
- 展开域名弹窗固定头部与底部操作区，仅结果列表滚动；域名与来源同排、IP 列表另起一行，失败时可直接重试。
- 页面标题、窗口标题与应用名称统一为「Hosts 优选订阅」；中文字体栈与等宽字体分别由 `--sans` / `--mono` 变量控制。
- 页面底部「设置与关于」面板集中管理令牌、外观主题、版本信息（编译版本号由入口传入）、GitHub 项目地址、使用说明与「检查更新」；独立「关于」卡片已移除。域名列表区块默认折叠。
- 历史趋势用原生 SVG 绘制平均延迟曲线。
- 日志面板轮询 `/api/logs`，支持自动刷新、关键字筛选、清空视图。
- 主题支持浅色/深色/跟随系统，选择存 `localStorage`。

## 9. 安全约束

- `run-as=package`，非 root；不使用 ICMP。
- 只监听一个高端口；请求体限制、探测超时与候选上限均有约束。
- 订阅地址仅绑内网 IP；管理接口需令牌（1.2.0 起），仍禁止直接暴露公网。
- 管理令牌持久化到共享目录 `admin-token`（0600），`HO_ADMIN_TOKEN` 可覆盖；常量时间比较防时序侧信道。
- `probe_dns` 的 UDP 上游必须是字面 IP；DoT/DoH 允许主机名，由 TLS 校验。
- 证书校验默认开启，CA 缺失时降级为系统证书池并告警。

## 10. 构建与发布

```bash
# 本地（无网络依赖）
cd core && GOPROXY=off go test ./...

# Windows 打包 x86 FPK（需要 fnpack 1.2.3）
set FNPACK=D:\path\fnpack.exe
powershell -File deploy/scripts/build-native-fpk.ps1 x86
```

产物：`deploy/dist/hosts-optimizer-native-<版本>-x86.fpk`。manifest 的发布者/开发者均为 `wulinwei959`，主页指向 GitHub 仓库；图标为 64/256 两档，1024 源图见 `deploy/icon-source.png`。

## 11. 测试

- 单元测试：`config`（含 DNS 默认值/环境变量/校验边界、扩展缓存 TTL、配置迁移）、`dnsquery`（含 DoT/DoH 与 wire format 交叉验证）、`dnsserver`（语义矩阵、父域回退、视图热替换、nil 安全、畸形不崩溃、TCP 往返/长度前缀/超限帧）、`probe`、`store`（滞回/候选持久化）、`history`（分片/保留期/过滤）、`app`（合并/定向选择/API、扩展缓存、刷新限流、healthz 字段、轮次锁六入口与超时作废、状态快照裁剪、更新检查端点）、`update`（版本比较、禁用 no-op）、`logfile`（轮转/重开追加）。CI 以 `go test -race` 覆盖竞态。
- 本地端到端：启动临时配置，验证探测、产物、ETag/304、异步刷新、历史、切换。
- 真机：fnOS x86 安装/卸载重装、启停、订阅端点、配置保留、1.0.x 功能回归。

## 12. 扩展与限制

- **SQLite 迁移**：历史层已抽象为 `history.Store`。当历史超过约 500 万行、需要复杂 SQL 或多写者时，可替换为纯 Go 的 `modernc.org/sqlite`（需 vendor，仍可离线构建）；当前 JSONL 方案足够。
- **DoQ**：需要第三方 QUIC 库，按零依赖约束不支持。
- **定向刷新不展开子域名**：只刷新勾选的域名，避免为少量域名触发昂贵的发现流程；手动整轮刷新则强制重新展开。
- **管理接口需令牌**：仅限内网使用；令牌在共享目录可见，属「内网便利 + 防误触」级别，非强对抗安全。
- **admin-token ACL 未收紧**：data-share 按用户名授权，不同 NAS 管理员名不同，硬编码脆弱，故不做（1.4.0 明确跳过）。

## 13. DNS 应答器

### 为什么另开一条路

AdGuard Home 的过滤器订阅刷新间隔最低为 1 小时，且 `$dnsrewrite` 本身是静态替换——`internal/filtering/dnsrewrite.go` 的 `processDNSRewrites` 只把应答记录换成写的 IP，没有 TTL、没有健康度概念。因此走订阅链路时，即使本服务已切到新 IP，客户端仍会在最长一个订阅周期内拿到旧 IP。

内置应答器让 AGH 以「普通上游」的方式按域名分流查询本服务，把生效上限交给 TTL。

### 匹配语义

与 AGH 的 `||domain^` 对齐：先精确匹配，未命中则逐级去掉最左侧标签向上找父域规则（`a.b.c` → `b.c` → `c`）。**不做后缀通配**：`githubusercontent.com` 不会被 `github.com` 规则命中。

`View.Lookup` 在构建时把所有域名规范化为小写无尾点，因此 `GITHUB.COM.` 与 `github.com` 等价。

### 语义矩阵

| 查询 | 应答 |
| --- | --- |
| A，命中且 IP 非空 | `NOERROR` + 1 条 A，TTL 取 `dns.ttl` |
| AAAA，命中 | `NOERROR` + 0 条（NODATA） |
| 其他 QTYPE，命中 | `NOERROR` + 0 条（只承诺 A/AAAA） |
| A，命中但 IP 为空 | `REFUSED` |
| 清单外域名 | `REFUSED` + 限频日志（每 100 条一条） |
| `QDCOUNT ≠ 1` / name 越界 / label > 63 / 总长 > 255 | `FORMERR`（QDCOUNT 置 0，不回显 question） |
| 短于 12 字节 | 静默丢弃并计入 `malformed` |
| `QCLASS ≠ IN` | `REFUSED` |
| QR=1 或 opcode ≠ QUERY | 静默丢弃 |

### wire format 要点

| 项 | 值 |
| --- | --- |
| header | 12 字节：ID(2) flags(2) QD(2) AN(2) NS(2) AR(2) |
| 应答 flags | `0x8000 \| (q.flags & 0x7800) \| (q.flags & 0x0100) \| rcode`，RA=0 |
| answer name | 压缩指针 `0xC00C`（指向偏移 12 的 question name） |
| A RDATA | `net.ParseIP(ip).To4()`，RDLENGTH=4 |
| EDNS | 查询带 OPT 时**不回显**，合法且 AGH 兼容 |
| FORMERR 例外 | QDCOUNT 写 0，不回显 question |
| UDP 读缓冲 | 4096 |
| 并发模型 | 单 read loop + 每包一 goroutine + `defer recover()` |

### TCP 支持（1.4.0）

部分解析器在应答截断或纯 TCP 场景会回退到 TCP，应答器因此在**同一端口**同时监听 UDP 与 TCP：

- `Serve` 先 `ListenUDP`，再用 UDP 实际端口 `net.Listen("tcp", …)`（端口 0 场景必须复用 UDP 拿到的真实端口，否则各占一个临时端口）。TCP 监听失败仅记日志、继续 UDP（非致命）。两个 socket 都绑定后才置 `Started`。
- 应答构造抽象为 `write func([]byte) error`：UDP 用 `WriteToUDP`，TCP 用带写超时的 `Write`；`handlePacket` 与计数逻辑两路复用。
- **RFC 1035 帧**：请求与应答都带 2 字节大端长度前缀。读帧上限 `maxTCPFrame=4096`；超限帧按声明长度丢弃以保持帧同步并计入 `malformed`。
- 每连接读超时 `tcpIdleTimeout=30s`、写超时 `tcpWriteTimeout=5s`，避免慢客户端长期占用 goroutine；`ctx` 取消时关闭 listener 与连接。
- 语义矩阵、`View` 匹配、计数与 UDP 完全一致；测试覆盖 A 往返、长度前缀、超限帧计数与帧同步恢复。

### 视图与生命周期

- `Server.view` 是 `atomic.Pointer[View]`，`SetView` 直接 store；查询路径无锁读。
- `Server.conn` 也必须是 `atomic.Pointer[net.UDPConn]`：`Addr()` 要在 `Serve` 之前（端口 0 场景）和之后都能安全读，普通字段会有数据竞争。
- 计数全部 `sync/atomic`；`LastQueryAt` 用 `atomic.Int64` 存 UnixNano。
- `dnsserver.New("")` 返回 `nil` 是设计而非错误，所有公开方法对 nil 接收者安全。
- `New()` 中 `initDNSServer` 必须**先于** `recoverSnapshot`：恢复流程会调 `applyDNSSnapshot`。
- `Run()` 中 `errCh` 容量为 2（HTTP 与 DNS 两个生产者）；DNS 监听失败作为致命错误返回，交由 `Restart=always` 拉起。

### 四个快照更新点

任一快照变化后都必须调 `applyDNSSnapshot`，漏一处就会出现「产物已更新但 DNS 仍答旧 IP」：

1. `recoverSnapshot()`——先读 `status.json` 恢复视图，再读 `hosts.txt` / `agh.txt`；
2. `doRoundFor()` 轮末 `a.snap = snap` 之后；
3. `handleSwitch()` 手动切换 `a.snap = built` 之后；
4. `removeFromSnapshot()` 禁用/删除域名 `a.snap = built` 之后。

TTL 与分流域名清单在 `doRoundFor` 加载配置后每轮跟随；此外 `PUT /api/domains` 与 `POST /api/disable` 写回配置后会立即调 `refreshDNSFamiliesFromConfig()`，因为**禁用后若仍留在 AGH 上游行里，AGH 会把查询送来而我们答 REFUSED，等于把用户网络解析搞挂**。

### 分流行格式

```
[/github.com/raw.githubusercontent.com/]127.0.0.1:18053
```

方括号内是**启用域名的完整名**而非注册域：`||domain^` 匹配该域名及全部子域，若只列注册域，已独立配置的子域会被父域规则劫持。禁用/删除域名后该行会即时收缩，需重新粘贴到 AGH。

### AGH 配置与持久化

AGH 与本服务同机部署时，可在 AGH「设置 → DNS 设置 → 上游 DNS 服务器」中把分流规则放在普通上游之前，并保留一个普通 DNS 作为未分流域名的兜底：

```
[/github.com/raw.githubusercontent.com/]127.0.0.1:18053
223.5.5.5
```

AGH 提供 `/control/dns_config` 配置接口，可通过 `upstream_dns` 数组热更新上游列表，无需重启 AGH。fnOS 应用中心中的 AGH 可能在升级或重启时用应用模板重新生成运行配置，因此自动化部署除了调用控制接口，还应同步更新以下两处：

- 运行配置：`/vol1/@appdata/AdGuardHome/AdGuardHome.yaml`
- 应用模板：`/vol1/@appcenter/AdGuardHome/bin/AdGuardHome.yaml`

真机 1.1.0 已验证：经 AGH 查询 `github.com` 与 `raw.githubusercontent.com` 返回本服务的优选 IP，TTL 为 60 秒；AAAA 返回 NODATA，`/api/dns` 计数同步增长。

### 配置入口

`defaults.dns.listen` / `defaults.dns.ttl` / `defaults.expect_status`，以及域名级 `expect_status` / `allow_private` 都可在「编辑域名清单」的图形化表单内修改；表单按「基本设置 / 高级探测参数 / DNS 应答器与子域名 / 域名列表」归集，接入模式（DNS 应答器 / AGH 订阅二选一）、性能档位、切换灵敏度、探测 DNS 与状态码白名单均为下拉预设，选择后写回具体数值，手改数值自动切回「自定义」。`formToConfig` 对空值一律 `delete`，不会把用户未设置的字段显式写进 `domains.json`。`off` 类词表（`off` / `disabled` / `none` / `0` / `false`）填在监听地址输入框内即可禁用应答器。

### 前端渲染注意点

域名列表使用 `table-layout:fixed`：`table-cell` 的 `max-width` 会被浏览器忽略，不固定列宽时一个超长域名就会把邻列顶开、造成状态文字与按钮重叠。flex 容器内的长文本项必须显式 `min-width:0`，否则 `max-width` + `text-overflow:ellipsis` 不生效。分流行由 `readonly input` 改为 `<pre>`：50+ 个域名在 input 内无法完整查看，且 `<input>` 也不能用 `Range` 可靠全选。


### 重启恢复

启动顺序：`initDNSServer(rt)` → `recoverSnapshot()` → `Run()`。`recoverSnapshot` 先读 `status.json` 建 `Snapshot{Status: st}` 并刷新视图，所以即使 `hosts.txt` / `agh.txt` 缺失，重启后应答器也立即可服务。

### 安全

默认只监听 `127.0.0.1`，与 AGH 同机部署时最安全。改为 `0.0.0.0` 对外监听时必须自行加防火墙：应答器无鉴权，任何能访问该端口的人都能让这些域名指向你选的 IP。
