# IP 优选（ip-optimizer）

在 NAS 上自建的**私有「域名 → 优选 IP → AdGuard Home 订阅」生成器**。自己维护一小撮域名，从这台 NAS 所在宽带的视角定时探测最快且证书合法的 IP，生成可被 AdGuard Home 订阅的 hosts / dnsrewrite 规则。

定位类似 [GitHub520](https://github.com/521xueweihan/GitHub520)，但有三个关键区别：

| | GitHub520 | 本项目 |
| --- | --- | --- |
| 域名清单 | 硬编码 40 个 GitHub 域名 | 任意域名，`domains.json` 自行维护 |
| 产物 | GitHub Actions 公开订阅 | 内网 HTTP 订阅，公开订阅被刷的风险不存在 |
| 分发 | `Hosts` 文件 | fnOS 原生 FPK（单静态二进制，无 Docker、无运行时依赖） |

> **难点不在测速，而在「最快 IP ≠ 正确 IP」。** 一旦允许添加任意域名，只按 TCP 延迟选出来的很可能是「端口开着但不承载该域名」的错误 IP（CDN 边缘、劫持、泛解析）。因此本项目把工程量放在**候选合法性校验、滞回防抖、失败不覆盖**上，而不是把测速做得多快。

仓库：<https://github.com/wulinwei959/ip-optimizer>

当前版本：**1.4.0**（版本历史与验证记录见 [`docs/progress.md`](docs/progress.md)）

---

## 工作原理

```
domains.json
   ↓ DNS 采集：UDP / DoT / DoH（手写报文，无第三方库）
   ↓ 过滤回环 / 私有 / CGNAT / 保留段
候选 IP 池
   ↓ TCP 握手测速 ×3 取中位数
   ↓ TLS/SNI 证书链校验（InsecureSkipVerify=false）  ← 核心区分力
   ↓ 滞回决策（新 IP 需快 ≥N% 且连续胜出 M 轮）
   ↓ 原子写（CreateTemp → Sync → Rename）
hosts.txt / agh.txt / status.json
   ↓ 单端口 HTTP（ETag / 304 / POST /refresh）
AdGuard Home 订阅
```

更快的一条路（推荐，二选一）：

```
快照更新 → 内存视图原子替换 → UDP DNS 应答器（TTL 默认 60s）
   ↑ AGH 按域名分流直连：[/github.com/...]127.0.0.1:18053
```
```

两条防循环依赖的硬约束：

- `probe_dns` 支持明文 UDP（必须是字面 IP）、DoT（`tls://主机[:853]`）与 DoH（`https://主机/路径`），可混用；所有上游都必须绕开本机 AdGuard Home —— 否则「用待优化的解析结果去找候选 IP」形成循环依赖。DoQ 需要第三方 QUIC 库，本项目坚持零依赖，因此不支持。
- 订阅地址用 NAS **内网 IP**，不要填公网域名。

核心用 **Go 标准库、零第三方依赖**（`go.mod` 仅 `module hosts-optimizer` + `go 1.21`），`CGO_ENABLED=0` 交叉编译成单个静态 ELF。构建脚本强制 `GOPROXY=off`：一旦误引入第三方依赖会直接构建失败，而不是偷偷联网。

---

## 特性

- **离线**：唯一一次性联网是安装 Go SDK；之后构建与 fnOS 设备安装全程离线，不拉镜像、不装运行时、不 `pip install`。
- **非 root 安全**：`run-as=package`，只做 TCP/TLS 探测（不用 ICMP，因无 `cap_net_raw`），仅监听一个高端口。
- **失败不覆盖**：整轮校验全灭时保留上一轮产物，`hosts.txt` / `agh.txt` 返回 503 但绝不写空列表；`status.json` 仍为 200 并说明原因。
- **配置热加载**：每轮重新读取 `domains.json`，增删域名下一轮自动生效；也可 `POST /refresh` 立即重跑，无需重启。
- **重启可恢复**：启动时先读 `status.json` 恢复应答视图，再读磁盘上的本轮产物；不必等首轮探测结束就能对外提供订阅，也不会出现分流域名的解析真空期。
- **内置 DNS 应答器**：额外监听一个 UDP 端口，把 AGH 送来的域名查询直接答成优选 IP。IP 切换的生效时间从「AGH 订阅刷新间隔（最低 1 小时）」降到「一个 TTL（默认 60 秒）」。域名匹配与 AGH 的 `||domain^` 对齐：精确匹配 + 向父域回退，不做后缀通配。命中但无可用 IP 时返回 `REFUSED`，宁可解析失败也不返回旧 IP。状态页「接入方式」卡片提供一键复制的分流规则与运行计数。
- **接入模式二选一**：「基本设置 → AGH 接入模式」下拉选择 DNS 应答器（推荐）或 AGH 订阅（兼容），切换即时写回配置并秒级生效——订阅模式自动禁用应答器，订阅地址卡片随模式切换显示；切回 DNS 应答器时自动恢复上次的监听地址。
- **域名发现**：在「编辑域名清单」输入主域名（如 `github.com`），自动从 CT 日志、字典与规则中发现相关子域名；下拉列表逐项勾选，点「添加」即可写入配置，无需手工抄写。
- **展开域名弹窗**：域名与来源同排、IP 列表另起一行，长列表独立滚动且不遮挡操作按钮；查询失败时显示原因并可直接重试。
- **统一命名与排版**：页面标题、窗口标题与应用名称统一为「Hosts 优选订阅」；优化中文字体栈、字号层级、表格等宽数字与图标标识。
- **关于面板**：页面底部新增「关于」，展示版本号、GitHub 项目地址与使用说明；域名列表整体可折叠，默认收起。
- **按主域名分组**：状态表按可注册主域名归类（如 `api.gitlab.com` 归入 `gitlab.com`），点分组标题展开该分类的全部域名；支持整组勾选、全部展开/收起。分组的展开状态保存在浏览器本地，禁用域名、禁用本组、勾选、切换 IP 或刷新完成后都不会自动收起，只有手动点击分组标题或「全部展开/收起」才会改变；清空搜索关键词后仍按上次的手动选择显示。
- **图形化配置**：表单按「基本设置 / 高级探测参数 / DNS 应答器与子域名 / 域名列表」归集，配置项合并、常用项做成下拉——接入模式（DNS 应答器 / AGH 订阅二选一）、性能档位、切换灵敏度、探测 DNS 与 HTTP 状态码白名单均有预设，选择即写回具体数值，手改数值自动切回「自定义」；单个域名的 SNI、端口、候选 IP、展开来源、状态码白名单、允许私网 IP 点该行「高级」展开。保存后自动写回 `domains.json` 并触发新一轮；需要精细控制时可切到 JSON 源码模式。
- **排版与窄屏适配**：表格固定列宽，长域名不会把邻列顶开导致文字重叠；分组标题过长时省略并悬停显示全名；窄屏下自动隐藏次要列、操作按钮改为网格堆叠。
- **加密 DNS 上游**：`probe_dns` 支持 UDP、DoT、DoH 混用，例如 `tls://dns.alidns.com`、`https://dns.cloudflare.com/dns-query`；DoQ 需第三方 QUIC 库，未引入。
- **主题跟随系统**：默认跟随系统的深/浅色设置，也可在页面手动切换「浅色 / 深色 / 跟随系统」，选择保存在浏览器本地。
- **应用内运行日志**：页面底部提供日志面板，内存保留最近 2000 行，支持增量刷新、暂停自动刷新、关键字筛选与清空视图，便于实时排查。
- **历史趋势**：每轮探测结果按月写入 `history/rounds-YYYYMM.jsonl.gz`（gzip 压缩），默认保留 12 个月；页面可按域名与时间范围查看平均延迟趋势和最近记录。
- **批量刷新选中**：展开主域名分组后可勾选单个域名或整组，点「刷新选中」只重跑这些域名，其余结果保持不变。
- **候选延时与手动切换**：点击表格中的延迟数值可查看本轮全部可连接 IP 的延迟，并手动切换当前生效 IP；切换会立即写入状态与订阅产物。
- **保存即显示**：新增域名保存后立即出现在分组中，未探测时标记「待探测」，可直接点行内「刷新」探测。
- **域名禁用**：单个域名可勾选「禁用」，域名组可用「禁用本组」整组切换；禁用域名不参与探测、从 `hosts.txt` / `agh.txt` 中移除，状态表显示「已禁用」，可随时启用。
- **AGH 规则刷新**：「刷新 AGH 规则」按钮只根据当前快照重新生成 `agh.txt`，不重新探测 DNS/TCP；手动刷新选中域名或切换 IP 后也会自动同步订阅文件。
- **异步刷新**：`POST /refresh` 立即返回 `task_id` 并在后台执行，页面轮询 `/api/refresh-status` 显示进度，长时间探测不再阻塞请求。
- **fnOS 桌面入口**：桌面图标以 iframe 窗口打开状态页，可查看生效 IP / 延迟、复制订阅地址、刷新选中域名或单独重写 AGH 规则；表格支持勾选与批量操作。
- **管理令牌鉴权**：管理端点需令牌，令牌持久化到用户可见共享目录 `admin-token`（重启复用），在「设置与关于」面板填入即可；`HO_ADMIN_TOKEN` 可固定覆盖。
- **用户可见数据目录**：配置、令牌、运行日志都落在文件管理器「应用文件」可见的共享文件夹，便于查看、编辑与备份；升级时旧配置自动一次性迁移，不丢域名。
- **DNS 应答器 TCP**：与 UDP 同端口监听 TCP（RFC 1035 长度前缀），供不支持纯 UDP 的解析器回退；语义与计数和 UDP 一致。
- **子域扩展缓存**：子域名发现结果按 TTL（默认 12 小时）缓存，定时轮次复用、手动刷新强制重新发现，显著降低重复发现开销。
- **健康探针与自适应探测**：独立探针分钟级发现失效/变慢的当前 IP 并触发即时轮次；常规轮次只测「当前 IP + Top-N 挑战者」，周期性全量扫描，整轮共用并发池。
- **刷新限流与手动检查更新**：手动刷新 10 秒最小间隔（超出 429）；「设置与关于」面板提供「检查更新」按钮，手动向 GitHub 查询新版本并展示结果（60 秒限流，`HO_UPDATE_CHECK=off` 可整体关闭）。

---

## 快速开始

### 路线 1：fnOS 真机（主轨，推荐）

1. **确认架构**：`uname -m` → `x86_64` 用 x86 包，`aarch64` 用 arm 包。`platform=all` 不可用（官方规定包内含架构专属二进制时必须分包）。
2. **获取安装包**：`.fpk` 二进制产物不入库（见 `.gitignore`），需本地构建（见下节）或从 Releases 下载（若已发布）。
3. **安装**：应用中心 → 右上角菜单 → 安装本地应用 → 选择 `.fpk`。安装完全离线。
4. **打开桌面图标**：若覆盖安装后图标未出现，在 NAS 上执行 `systemctl restart trim_app_center.service` 再刷新桌面。
5. **配置 AdGuard Home**（二选一）：

   **推荐：DNS 应答器。** 打开状态页的「接入方式」卡片，复制分流规则，粘贴到 AGH 的「设置 → DNS 设置 → 上游 DNS 服务器」末尾：

   ```
   [/github.com/raw.githubusercontent.com/]127.0.0.1:18053
   ```

   IP 切换后最多一个 TTL（默认 60 秒）即生效，不受 AGH 的 1 小时订阅刷新间隔限制。

   **兼容：过滤器订阅。** 在「过滤器 → DNS 封锁清单」添加订阅地址，更新间隔设为 1 小时。

   ```
   http://<NAS内网IP>:18088/agh.txt     # 推荐
   http://<NAS内网IP>:18088/hosts.txt   # /etc/hosts 语法，精确匹配、不覆盖子域
   ```

   `agh.txt` 使用 `||domain^$dnsrewrite=NOERROR;A;IP`，覆盖子域且让 AAAA 天然返回 NODATA（详见下方「已查证的坑」）。**该方式与上面的 DNS 应答器二选一，不要同时启用。**
6. **配置域名**：打开状态页，在「编辑域名清单」的图形化表单里调整参数或增删域名；也可输入主域名点「获取域名列表」，勾选后批量添加，最后点「保存并生效」。需要直接改 JSON 时切换到「JSON 源码」，或编辑共享目录里的 `domains.json`（文件管理器「应用文件」→ hosts-optimizer → data）。

> 若用 HTTPS 访问飞牛桌面，iframe 加载 `http://...:18088` 可能被浏览器按混合内容拦截，表现为窗口空白。此时改用浏览器直接访问 `http://<NAS_IP>:18088/`，或把 `app/ui/config` 的 `type` 改为 `url`。

### 路线 2：本地开发（无需 NAS）

```bash
cd core
mkdir -p /tmp/ho-config /tmp/ho-out /tmp/ho-state
cp ../deploy/config-schema/domains.example.json /tmp/ho-config/domains.json

HO_CONFIG=/tmp/ho-config HO_OUTPUT=/tmp/ho-out HO_STATE=/tmp/ho-state HO_PORT=18088 \
  go run ./cmd/hosts-optimizer

# 另开终端
curl http://127.0.0.1:18088/status.json
curl -X POST http://127.0.0.1:18088/refresh
curl http://127.0.0.1:18088/hosts.txt
```

`HO_CONFIG` 指向**目录**，目录内必须有 `domains.json`。Windows 下把 `/tmp/...` 换成任意本地目录（如 `%TEMP%\ho-config`），环境变量用 PowerShell 的 `$env:HO_CONFIG = "..."` 设置。其他命令：

```bash
go run ./cmd/hosts-optimizer -check-config   # 只校验配置，不启动服务
go run ./cmd/hosts-optimizer -version
GOPROXY=off go vet ./... && GOPROXY=off go test ./...
```

### 路线 3：Docker Compose（已冻结，可选）

```bash
cd deploy/compose
cp .env.example .env
mkdir -p config && cp ../config-schema/domains.example.json config/domains.json
sudo docker compose up -d
```

该轨道需要镜像分发链路，作为可选形态保留，非首版交付物。

---

## 构建与打包

一次性准备：**Go SDK**（≥ 1.21，实测 1.23.4）+ **fnpack 1.2.3**（[官方下载](https://developer.fnnas.com/docs/cli/fnpack/)，可用 `FNPACK=/path` 指定）。

```bash
# Linux / macOS / Git Bash
./deploy/scripts/build-native-fpk.sh x86        # amd64 + platform=x86
./deploy/scripts/build-native-fpk.sh arm        # arm64 + platform=arm
SKIP_PACK=1 ./deploy/scripts/build-native-fpk.sh x86   # 只编译，不调 fnpack
```

```powershell
# Windows PowerShell（本机无 bash/pwsh 时用这个等价脚本）
powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 x86
powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 arm
$env:SKIP_PACK='1'; powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 x86
```

产物：`deploy/dist/hosts-optimizer-native-<version>-<x86|arm>.fpk`。

构建脚本做的事：`GOOS=linux GOARCH=<arch> CGO_ENABLED=0` 交叉编译 → 注入静态二进制到 `app/bin/` → 复制配置模板 → 可选携带 `deploy/ca-bundle.crt` → 改写 `manifest.platform` → `fnpack build`。`fnpack` 会校验 manifest 必填字段、`config/privilege` 与 `config/resource` 合法 JSON、两个图标（64×64 / 256×256）、`app/`、`cmd/`、`wizard/` 以及 `app/{desktop_uidir}/` 目录。

---

## 配置

### 环境变量（`HO_*`）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `HO_CONFIG` | `.` | 配置**目录**，内含 `domains.json`；FPK 注入共享目录 `${DATA_DIR}`（1.4.0 起） |
| `HO_LEGACY_CONFIG` | 空 | 旧配置目录；主路径缺 `domains.json` 时从此一次性迁移（FPK 注入 `$TRIM_PKGETC`） |
| `HO_OUTPUT` | `./output` | 产物目录；FPK 注入 `$TRIM_PKGVAR/output` |
| `HO_STATE` | `./state` | 状态/历史目录；FPK 注入 `$TRIM_PKGVAR/state` |
| `HO_DATA` | 空 | 用户可见数据目录（FPK 共享文件夹）；令牌与日志落盘于此 |
| `HO_PORT` | `8088` | 监听端口；FPK 注入 `$TRIM_SERVICE_PORT`（`18088`） |
| `HO_TZ` | `Asia/Shanghai` | 时区，静态二进制自带 tzdata，不依赖宿主 `/usr/share/zoneinfo` |
| `HO_CA_BUNDLE` | 空 | 可选 CA 证书文件；**文件不存在时降级为仅用系统证书池，不是致命错误** |
| `HO_ADMIN_TOKEN` | 空 | 固定管理令牌；未设则读共享目录 `admin-token`，再无则生成并持久化 |
| `HO_SCHEDULE_MINUTES` | — | 覆盖 `defaults.schedule_minutes` |
| `HO_PROBE_DNS` | — | 覆盖上游 DNS，逗号分隔；UDP 用字面 IP，也可写 `tls://` / `https://` |
| `HO_PROBE_CONCURRENCY` | — | 覆盖 `defaults.concurrency` |
| `HO_PROBE_TOP_N` / `HO_PROBE_FULL_EVERY` | — | 自适应探测面：常规轮次挑战者数 / 每 K 轮全量扫描 |
| `HO_WATCH_INTERVAL_SECONDS` / `HO_WATCH_SWITCH_PERCENT` | — | 健康探针间隔 / 变慢触发阈值 |
| `HO_EXPAND_CACHE_TTL_HOURS` | `12` | 子域扩展缓存 TTL（1..240 小时） |
| `HO_UPDATE_CHECK` | 开 | 填 `off` 关闭 GitHub 新版本检查 |
| `HO_DNS_LISTEN` | — | 覆盖 `defaults.dns.listen`；填 off 类词表（`off` / `disabled` / `none` / `0` / `false`）禁用应答器 |
| `HO_DNS_TTL` | — | 覆盖 `defaults.dns.ttl` |

### `domains.json`

```json
{
  "domains": [
    { "name": "github.com" },
    { "name": "raw.githubusercontent.com", "sni": "raw.githubusercontent.com", "port": 443 }
  ],
  "defaults": {
    "schedule_minutes": 60,
    "probe_dns": ["223.5.5.5", "119.29.29.29"],
    "concurrency": 20,
    "hysteresis_percent": 20,
    "hysteresis_rounds": 2,
    "timeout_seconds": 3
  }
}
```

`domains[]` 还支持 `candidates`（固定候选 IP 池）、`expect_status`（在 TLS 连接上校验 HTTP 状态码，默认关闭）、`allow_private`。完整字段表、取值范围与校验规则见 [`deploy/config-schema/README.md`](deploy/config-schema/README.md)，示例见 [`deploy/config-schema/domains.example.json`](deploy/config-schema/domains.example.json)。

> 用 JSON 而非 YAML，是为了不引入 `go mod download`。

### HTTP 端点（单端口）

| 路径 | 说明 |
| --- | --- |
| `/` | 概览页：状态表格、复制订阅地址、批量刷新、候选 IP 切换、历史与日志 |
| `/hosts.txt` | `IP domain` 逐行，`/etc/hosts` 语法 |
| `/agh.txt` | `\|\|domain^$dnsrewrite=NOERROR;A;IP`，推荐 |
| `/status.json` | 每域名候选数、通过数、生效 IP、延迟、切换原因、本轮时间 |
| `POST /refresh` | 提交后台刷新任务，立即返回 `202` 与 `{"ok":true,"task_id":"r..."}`；可选 JSON 体 `{"domains":["a.com"]}` 只刷新指定域名；已有任务在跑时复用 |
| `GET /api/refresh-status?task_id=...` | 查询刷新进度：`state` 为 `running` / `done` / `error`，完成时带 `next_round_minutes` |
| `GET /api/logs?after=<seq>&limit=<n>` | 增量读取运行日志，返回 `entries` 与 `last_seq`；缓冲上限 2000 行 |
| `GET /api/history?domain=&group=&from=&to=&limit=` | 查询探测历史；`from`/`to` 支持 RFC3339 或 `YYYY-MM-DD`，默认最近 7 天，`limit` 上限 5000 |
| `GET /api/candidates?domain=<域名>` | 返回该域名最近一轮全部可连接 IP 与延迟、当前生效 IP |
| `POST /api/switch` | 手动切换：JSON 体 `{"domain":"a.com","ip":"1.2.3.4"}`，IP 必须在该域名最近候选列表中 |
| `POST /api/refresh-agh` | 只用当前快照重写 `agh.txt`，返回字节数，不触发探测 |
| `POST /api/disable` | 启用/禁用域名：`{"names":["a.com"],"disabled":true}` 或 `{"group":"github.com","disabled":true}`；禁用后立即从产物移除 |
| `GET /api/domains` | 读取 `domains.json` 原文 |
| `PUT /api/domains` | 校验并原子写回 `domains.json`（要求 `Content-Type: application/json`） |
| `POST /api/expand` | 按需发现主域名的相关子域名，返回解析结果（不修改配置） |
| `GET /api/dns` | 应答器状态：`enabled` / `listen` / `addr` / `ttl` / 运行计数 / `agh_upstream` 分流规则 |
| `POST /api/update-check` | 手动检查 GitHub 新版本（60 秒限流），返回 `latest_version` / `update_available` |
| `GET /healthz` | 健康探针：版本、运行时长、`data_dir`、扩展缓存命中、`update_available` / `latest_version`、watchdog 统计（无需令牌） |

文本端点返回 `ETag` / `Last-Modified`，支持 `If-None-Match` → 304。

> **管理鉴权（1.2.0 起）**：`/api/*` 与 `/refresh` 需令牌（`X-Admin-Token` 头 / Bearer / `?token=`）。令牌在共享目录 `admin-token` 文件（文件管理器可见，重启不变），把它填进「设置与关于」面板的令牌输入框即可；`HO_ADMIN_TOKEN` 可固定覆盖。订阅端点与 `/healthz` 无需令牌。`POST /refresh` 有 10 秒最小间隔（超出返回 429），手动整轮刷新会强制重新展开子域名。

---

## fnOS 原生 FPK 集成要点

这些都踩过坑，改动前请先看清：

- **生命周期**：`cmd/main` 必须 `source` `cmd/common` 与 `cmd/service-setup`，并调用 `start_daemon` / `stop_daemon` / `daemon_status`。若 `start` 是空实现，App Center 的健康检查永远拿不到 PID，会无限重启。`start_daemon` 用 `eval "nohup $SERVICE_COMMAND &"` 让 `$!` 是二进制真实 PID。
- **桌面入口**：`manifest` 的 `desktop_uidir=ui` + `desktop_applaunchname=<ID>`，且 `<ID>` 必须同时是 `app/ui/config` 里 `.url` 的 key，并**不超过 32 字符**（`fnpack` 硬校验）。`type` 用 `iframe` 才在 fnOS 桌面窗口内打开；`url` 会跳到单独网页。
- **权限**：Windows 打包会丢 Unix 执行位，导致目录变成 `0644` 无法进入、二进制无 `x` 无法执行。`cmd/install_callback` 在真机安装时 `chmod 755` 补回（比改 fpk 内 tar 可靠，也不破坏 checksum）。
- **行尾**：仓库用 `.gitattributes` 锁定 `* text=auto eol=lf`。CRLF 或 BOM 进到 `#!/bin/bash` 脚本里会直接失效。
- **CA 证书**：静态二进制优先 `x509.SystemCertPool()`；实测 fnOS 上可对 `github.com` / `raw.githubusercontent.com` 完成 TLS 校验。若目标设备读不到系统 CA，把证书放到 `deploy/ca-bundle.crt`，构建脚本会随包携带并自动启用。

---

## 目录结构

```
.
├── core/                          # Go 核心（仅标准库）
│   ├── cmd/hosts-optimizer/       # 入口：-version / -check-config / 服务
│   └── internal/{config,dnsquery,probe,store,output,app,util,history,logbuf}
├── deploy/
│   ├── fnos-native-fpk/           # 主轨：fnOS 纯原生 FPK 源工程
│   │   ├── manifest
│   │   ├── cmd/{main,common,service-setup,install_callback,...}
│   │   ├── app/ui/config          # 桌面入口定义
│   │   ├── app/ui/images/         # 桌面图标
│   │   ├── config/{privilege,resource}
│   │   └── wizard/install
│   ├── fnos-docker-fpk/           # 轨道 B（冻结）
│   ├── compose/                   # 轨道 A（冻结）
│   ├── config-schema/             # domains.json 说明 + 示例
│   ├── scripts/                   # 构建脚本（.sh / .ps1）
│   └── dist/                      # 构建产物（不入库）
├── research/                      # 调研与方案决策（2026-11-05 快照）
├── .gitignore / .gitattributes
└── README.md
```

运行时数据（fnOS 原生包）：

- 配置：`/vol1/@appshare/hosts-optimizer/data/domains.json`（1.4.0 起，文件管理器「应用文件」可见；旧位置 `@appconf` 启动时自动迁移）
- 管理令牌：`/vol1/@appshare/hosts-optimizer/data/admin-token`（重启复用）
- 运行日志：`/vol1/@appshare/hosts-optimizer/data/logs/app.log`（8MB 轮转）
- 产物：`/vol1/@appdata/hosts-optimizer-native/output/`
- 状态与历史：`/vol1/@appdata/hosts-optimizer-native/state/`（`state.json` + `history/rounds-YYYYMM.jsonl.gz`）

---

## 三种形态与取舍

| 轨道 | 形态 | 状态 |
| --- | --- | --- |
| C | fnOS 纯原生 FPK（单二进制 + systemd） | **主轨，首版交付** |
| A | 通用 Docker Compose | 冻结（可选） |
| B | fnOS Docker 类 FPK | 冻结（可选） |

决策依据不是维护成本，而是**构建期联网依赖**：Docker 轨要构建并分发镜像，依赖下载链路长；原生 FPK 只需把本机编译好的一个 ELF 放进 `app/bin/`，`fnpack build` 是纯本地文件操作。

---

## 当前验证状态

**已验证**

- `GOPROXY=off` 下 `go vet` / `go test ./...`（全部包单测）、双架构静态 ELF 交叉编译通过。
- 本机端到端：`/status.json` 200、`ETag` → 304、`POST /refresh` 202 + 状态轮询到 `done`、三份产物落盘；失败路径保留上一轮结果且 `hosts.txt` 返回 503。
- `fnpack build` 通过并产出 x86 `.fpk`；包结构、manifest 字段与桌面入口文件已解包核对。
- **真机 1.0.0**：二进制以包用户（uid 900）运行可监听、抓取、写产物，SIGTERM 干净退出；`github.com` / `raw.githubusercontent.com` 的 TLS 校验通过并产出真实 IP；无限重启问题已修复。
- **真机 1.0.1**：`app stop` / `app start` / `app restart` 均返回成功，应用中心状态与真实进程一致；卸载重装后 `domains.json`、`output/`、`state/` 保留；`/`、`/status.json`、`/hosts.txt`、`/agh.txt` 均返回 200，`ETag` → 304；`10350` 已修复。
- **真机 1.0.2**：卸载重装后配置与产物保留，页面显示 18 个域名、17 个生效；`/`、`/status.json`、`/hosts.txt`、`/agh.txt` 均 200，`ETag` → 304；`POST /refresh` 返回 `202` + `task_id`，约 93 秒后轮询到 `state=done`（旧同步接口会超时），期间页面不阻塞；`/api/expand` 对 `github.com` 返回 50 个相关域名（12 个可解析），下拉勾选与「添加」写入配置正常；`app stop` / `app start` 均成功。
- **真机 1.0.3**：卸载重装后配置与产物保留；状态表按主域名分组（如 `cloudflare.com` 7 个、`github.com`、`githubusercontent.com` 等），分组展开/收起与整组勾选正常；图形化表单正确带出轮询周期 60、端口 443、并发 20、候选 64、TCP 3 轮、超时 3 秒等参数，域名列表可编辑。
- **真机 1.0.4**：把 `probe_dns` 临时改为 `https://dns.alidns.com/dns-query` + `tls://dns.alidns.com`，一轮约 75 秒完成，17/18 域名生效且候选数正常，验证后已恢复原配置；`quic://` 地址被配置校验拒绝并返回明确提示。
- **真机 1.0.5**：页面默认跟随系统显示深色主题，手动切换浅色/深色后刷新仍保持；运行日志面板显示启动与探测日志（增量序号正常），关键字筛选可用；FPK manifest 的 `maintainer` / `distributor` 均为 `wulinwei959`，链接指向项目 GitHub。
- **真机 1.0.6**：启动轮次自动写入 `history/rounds-202611.jsonl.gz`，两轮共 36 条记录；页面历史趋势可按域名与时间范围查询，平均延迟曲线与最近记录正常；重装后历史保留；FPK 内 64/256 图标尺寸正确。
- **真机 1.0.9**：点击延迟可查看 4 个候选 IP 及延迟并手动切换生效；「刷新选中」只探测选中域名，完成后日志显示「AGH 订阅已同步」；「刷新 AGH 规则」只重写订阅文件且不触发探测。
- **真机 1.0.10**：在图形化「域名列表」新增 `example.org` 并保存，页面立即出现该分组与「待探测」行（30/36）；移除后恢复 30/35，配置与分组一致。
- **真机 1.1.0**：通过 fnOS 应用中心覆盖安装 x86 FPK，版本、配置、历史与产物均正确保留；内置 DNS 应答器监听 `127.0.0.1:18053`，AGH 通过完整分流规则直连本服务，经 AGH 查询 `github.com` / `raw.githubusercontent.com` 均返回优选 IP，TTL 为 60 秒，AAAA 返回 NODATA。

**待验证 / 已知限制**

- 桌面入口在 fnOS 桌面内的实际显示仍需人工确认；覆盖安装后可能需要重启 `trim_app_center.service`。
- AdGuard Home DNS 分流已接入测试环境，长期稳定性与不同客户端的解析表现仍需持续观察。
- 真实公网域名下的一周 IP 抖动、滞回表现与多源 DNS 并集质量未长期观测。
- 刷新任务保存在进程内存：服务重启后状态丢失（不影响已落盘产物），重新触发即可。
- A / B 轨道未验证；`config/resource` 的 `data-share` 共享目录编辑方案未启用。
- `x509.SystemCertPool()` 在个别精简 fnOS 版本可能读不到系统 CA，此时需随包 `ca-bundle.crt`。

首次安装、启停重启、卸载重装、配置与产物保留、全灭时保留上一轮，以及真实 AdGuard Home DNS 分流均已在真机验证。

---

## 已查证的坑

- **AdGuard Home 的 `AAAA` 空值规则非法**：`||domain^$dnsrewrite=NOERROR;AAAA;` 会被 urlfilter 判为非法（VALUE 必须是合法 IPv6）。而 `dnsrewrite` 规则本身会替换整个 DNS 应答，AAAA 查询天然返回空 NOERROR（NODATA），所以 `agh.txt` **不输出任何 AAAA 规则**。这也是推荐 `agh.txt` 而非 `hosts.txt` 的原因之一。
- **`fnpack` 入口 ID 上限 32 字符**：超了直接 `Packing failed`。
- **Windows 打包丢 x 位**：目录 `0644` 无法进入，见上节 `install_callback` 的 `chmod`。
- **CRLF / BOM**：会让 `#!/bin/bash` 或 JSON 入口配置失效，见 `.gitattributes`。
- **`pkill -f` 会误杀生命周期脚本**：`cmd/main` 路径本身包含 `hosts-optimizer`，用 `pkill -f "hosts-optimizer"` 会连正在执行 stop 的脚本一起杀掉，应用中心收到非零退出码并报 `10350`，表现为“进程已停止但操作失败”。必须用 `pidof` / `pgrep -x` 按进程名精确匹配；1.0.1 已修复并加入回归测试。

---

## 文档索引

| 文档 | 内容 |
| --- | --- |
| [`deploy/README.md`](deploy/README.md) | 部署适配层：三形态取舍、接口契约、构建细节 |
| [`deploy/config-schema/README.md`](deploy/config-schema/README.md) | `domains.json` 全字段表、HTTP 端点、IPv6 结论 |
| [`docs/technical.md`](docs/technical.md) | 技术文档：架构、数据模型、API、并发、构建与扩展 |
| [`docs/progress.md`](docs/progress.md) | 项目进度：版本历史、功能矩阵、验证记录、路线图 |
| [`research/2026-11-05-nas-hosts-ip-optimizer.md`](research/2026-11-05-nas-hosts-ip-optimizer.md) | 需求与开源复用调研（2026-11-05 快照） |
| [`research/2026-11-05-fnos-dual-deployment.md`](research/2026-11-05-fnos-dual-deployment.md) | fnOS FPK 契约核查、验收清单、方案决策 |

> `research/` 是 2026-11-05 的调研快照，其中「未验证」描述的是当时状态，不代表当前进度；以本文件的「当前验证状态」为准。

---

## 许可

仓库尚未声明 LICENSE。如需公开分发或他人复用，请先补充许可证文件。

## 贡献指南

详见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，包含：
 - Git 提交规范（中文标签、说明、注释）
 - 合并策略（Squash and merge）
 - 开发环境与本地验收清单
 - FPK 打包验证
 - 关键设计约束
