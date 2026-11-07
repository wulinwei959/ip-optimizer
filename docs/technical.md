# 技术文档

> 适用版本：1.0.15 · 更新：2026-11-07
>
> 本文描述内部实现与数据契约；配置字段与部署步骤见 [`deploy/config-schema/README.md`](../deploy/config-schema/README.md) 与 [`deploy/README.md`](../deploy/README.md)。

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
| `internal/expand` | 子域名发现：CT 日志、字典、内置规则 |
| `internal/app` | HTTP 路由、探测编排、异步任务、快照管理、管理 API |

## 3. 一轮探测

1. `config.Load()` 重新读取 `domains.json`（热加载，无需重启）。
2. 解析目标：显式域名优先，随后对 `expand=true` 的域名做子域名发现（仅全量轮次）。
3. 候选采集：`dnsquery.CollectWithOptions` 并发查询所有上游，过滤回环/私有/CGNAT/保留段。
4. 探测校验：TCP 握手多轮取中位数，再做 TLS 握手与证书链校验（`InsecureSkipVerify=false`）。
5. 决策：`store.Decide` 应用滞回（默认新 IP 需快 ≥20% 且连续 2 轮胜出）。
6. 落盘：`output.Build` 生成三份产物，`util.AtomicWrite` 以「临时文件 → Sync → Rename」写入。
7. 历史：每域名一行写入当月 `history/rounds-YYYYMM.jsonl.gz`。
8. 快照：在 `a.mu` 保护下替换内存快照，订阅端点立即读到新内容。

### 全量与定向刷新

- `POST /refresh`（无 body）执行全量轮次。
- `POST /refresh {"domains":["a.com"]}` 只探测指定域名：不做子域名发现，结果通过 `mergeEntries` 合并回现有快照，其余域名保持不变。
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
| `/vol1/@appconf/hosts-optimizer-native/domains.json` | 配置 |
| `/vol1/@appdata/hosts-optimizer-native/output/` | `hosts.txt` / `agh.txt` / `status.json` |
| `/vol1/@appdata/hosts-optimizer-native/state/state.json` | 每域名当前 IP、滞回状态、最近候选列表 |
| `/vol1/@appdata/hosts-optimizer-native/state/history/` | `rounds-YYYYMM.jsonl.gz` 历史分片 |

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

写接口要求 `Content-Type: application/json`（阻止简单跨站表单），但**没有登录鉴权**，只应部署在内网。

## 7. 并发与一致性

| 锁 | 保护对象 | 说明 |
| --- | --- | --- |
| `roundMu` | 探测轮次、手动切换、AGH 重建 | 串行化所有会改产物/状态的操作 |
| `refreshMu` | `refreshTask` | 异步任务状态；已有任务时复用 |
| `stateMu` | `store.State` | 每域名决策与候选列表读写 |
| `mu` | `snap` 快照 | 订阅端点读、轮次结束替换 |

产物只通过 `AtomicWrite` 更新，读端不会看到半截文件。

## 8. 前端

- 单个 `html/template` 字符串，无打包步骤、无外部 CDN。
- 状态表按可注册主域名分组，支持展开/收起、整组勾选、批量刷新/删除。分组展开状态存放在浏览器 `localStorage` 的 `ho-group-open` 键（`{主域名: bool}`），只有点击分组标题与「全部展开/收起」会写入；禁用域名、禁用本组、勾选、切换 IP、保存配置或刷新完成后触发页面重载时据此恢复，不会被自动收起。搜索命中时的展开是临时的（不写入存储），清空关键词后只还原这些临时展开的分组。
- 表格会合并「配置中的域名」与「本轮状态」：尚未探测的域名以「待探测」行展示，保存后即可看到并直接刷新。
- 延迟单元格可打开候选 IP 弹窗并手动切换。
- 展开域名弹窗固定头部与底部操作区，仅结果列表滚动；域名与来源同排、IP 列表另起一行，失败时可直接重试。
- 页面标题、窗口标题与应用名称统一为「Hosts 优选订阅」；中文字体栈与等宽字体分别由 `--sans` / `--mono` 变量控制。
- 页面底部「关于」展示编译版本号（由入口传入）、GitHub 项目地址与使用说明；域名列表区块默认折叠。
- 历史趋势用原生 SVG 绘制平均延迟曲线。
- 日志面板轮询 `/api/logs`，支持自动刷新、关键字筛选、清空视图。
- 主题支持浅色/深色/跟随系统，选择存 `localStorage`。

## 9. 安全约束

- `run-as=package`，非 root；不使用 ICMP。
- 只监听一个高端口；请求体限制、探测超时与候选上限均有约束。
- 订阅地址仅绑内网 IP；管理接口无鉴权，禁止直接暴露公网。
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

- 单元测试：`config`、`dnsquery`（含 DoT/DoH）、`probe`、`store`（滞回/候选持久化）、`history`（分片/保留期/过滤）、`app`（合并/定向选择/API）。
- 本地端到端：启动临时配置，验证探测、产物、ETag/304、异步刷新、历史、切换。
- 真机：fnOS x86 安装/卸载重装、启停、订阅端点、配置保留、1.0.x 功能回归。

## 12. 扩展与限制

- **SQLite 迁移**：历史层已抽象为 `history.Store`。当历史超过约 500 万行、需要复杂 SQL 或多写者时，可替换为纯 Go 的 `modernc.org/sqlite`（需 vendor，仍可离线构建）；当前 JSONL 方案足够。
- **DoQ**：需要第三方 QUIC 库，按零依赖约束不支持。
- **定向刷新不展开子域名**：只刷新勾选的域名，避免为少量域名触发昂贵的发现流程。
- **管理接口无鉴权**：仅限内网使用。
