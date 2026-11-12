# 部署适配层骨架

本目录只解决**部署与分发**，不含业务核心实现。

当前版本 **1.5.0**；技术实现见 [`docs/technical.md`](../docs/technical.md)，版本历史与验证记录见 [`docs/progress.md`](../docs/progress.md)。

## 当前取舍：主轨 = fnOS 纯原生 FPK

| 目录 | 形态 | 状态 |
| --- | --- | --- |
| `fnos-native-fpk/` | 纯原生 FPK（单静态二进制 + systemd） | **主轨，首版交付** |
| `compose/` | 通用 Docker Compose | 冻结（可选） |
| `fnos-docker-fpk/` | fnOS Docker 类 FPK | 冻结（可选） |

决策依据：**构建期联网依赖**。Docker 轨要构建并分发镜像，依赖下载链路长；原生 FPK 只需把本机编译好的一个 ELF 放进 `app/bin/`，`fnpack build` 是纯本地文件操作，设备安装阶段完全离线——不拉镜像、不装运行时、不 `pip install`。

**一个必须澄清的点**：原生 FPK ≠ Python 运行时。本骨架初版是 `python312 + venv + pip install`，这条恰好会卡死在依赖下载，已整体移除。飞牛官方 `environment-variables.md` 的 `cmd/main` 示例本身就是 `./myapp --config ... &`；`fnos-apps` 的 Gopeed 原生包 `manifest` 里**没有** `install_dep_apps`，靠自带的 `gopeed` 二进制运行（证据见研究报告第 10 节）。

## 核心工程的技术约束（决定能否真的离线）

- **Go + 仅标准库**：`net/http`（单端口服务）、`crypto/tls`（SNI 证书校验 / DoT）、`encoding/json`（配置）、`net`（自定义 DNS 查询：UDP / DoT / DoH，手写报文）、`time.Ticker`（进程内定时）、`os.Rename`（原子写）。全部标准库，无 `go mod download`。
- **唯一一次性联网**：在本机装 Go SDK（单个安装包）。之后所有构建离线；`build-native-fpk.sh` 设 `GOPROXY=off GOSUMDB=off`，一旦误引入第三方依赖会**直接构建失败**而不是偷偷联网。
- **交叉编译**：Windows 上 `GOOS=linux GOARCH=amd64|arm64 CGO_ENABLED=0 go build` 直接产出 Linux 静态 ELF，不需要 Linux 机器、Docker daemon、基础镜像。
- **CA 根证书**：静态二进制不自带系统信任库。核心优先 `x509.SystemCertPool()`（fnOS 为 Debian 系，一般可用）；`HO_CA_BUNDLE` 指向的随包 `ca-bundle.crt` 为可选增强（放到 `deploy/ca-bundle.crt` 即会被构建脚本带入包）。**文件不存在时仅告警并降级为系统证书池，不致命退出** —— 早期把它当致命错误处理，曾导致 `Restart=always` 无限重启。
- **配置用 JSON**：YAML 需要第三方模块。调度改为 `defaults.schedule_minutes`（整数分钟），进程内定时，不依赖宿主 crontab（非 root 也装不了）。

## 构建（本机离线）

一次性准备：

1. 安装 Go SDK（≥ 1.21）
2. 下载 fnpack 1.2.3，重命名为 `fnpack` 加入 PATH（或用 `FNPACK=/path` 指定）
3. 核心工程已在 `core/`（含 `go.mod` 与 `./cmd/hosts-optimizer`）

Linux / macOS / Git Bash：

```bash
SKIP_PACK=1 ./deploy/scripts/build-native-fpk.sh x86   # 只编译，不调 fnpack
./deploy/scripts/build-native-fpk.sh x86
./deploy/scripts/build-native-fpk.sh arm
# → deploy/dist/hosts-optimizer-native-<版本>-x86.fpk / -arm.fpk
```

Windows PowerShell（开发机没有 bash / pwsh 时用这份等价脚本；脚本为纯 ASCII，规避中文 GBK/UTF-8 编码问题）：

```powershell
powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 x86
powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 arm
$env:SKIP_PACK='1'; powershell -NoProfile -File deploy/scripts/build-native-fpk.ps1 x86
```

`platform=all` **不再可用**（官方 `manifest.md`：`all` 仅当包内不含特定架构二进制）。脚本按参数把 `manifest` 改成 `platform=x86` / `arm`，因此必须分发两个包，用户按设备架构选。

安装（建议用专门的 fnOS 测试设备）：

```
应用中心 → 右上角菜单 → 安装本地应用 → 选择 .fpk
```

**接入 AdGuard Home（二选一，不要同时启用）**

- **推荐：DNS 应答器。** 打开状态页「接入方式」卡片，复制分流规则，粘贴到 AGH 的「设置 → DNS 设置 → 上游 DNS 服务器」末尾，形如 `[/github.com/raw.githubusercontent.com/]127.0.0.1:18053`。IP 切换后最多一个 TTL（默认 60 秒）即生效，不受 AGH 订阅刷新间隔限制。
- **兼容：过滤器订阅。** 订阅地址推荐 `http://<NAS内网IP>:18088/agh.txt`（覆盖子域且 AAAA 天然 NODATA），或 `http://<NAS内网IP>:18088/hosts.txt`。在 AdGuard Home「过滤器 → DNS 封锁清单」添加，更新间隔改为 1 小时。安装后也可从桌面图标打开的状态页一键复制订阅地址。

应答器的 UDP 端口（默认 `18053`）与 HTTP 端口（`18088`）是两条独立链路，FPK 只需 `service_port=18088`；DNS 端口由 `defaults.dns.listen` 控制。

打包校验要求：`manifest`、`config/privilege`(JSON)、`config/resource`(JSON)、`ICON.PNG`(64×64)、`ICON_256.PNG`(256×256)、`app/`、`cmd/`、`wizard/` 齐全。图标已替换为正式版本，修改时从 `deploy/icon-source.png` 重新导出 64/256 两档。

## 核心必须遵守的接口契约

- 单端口 HTTP：FPK 进程/宿主 `18088`（`TRIM_SERVICE_PORT`），Compose 容器内 `8088`
- 路径：`/`、`/hosts.txt`、`/agh.txt`、`/status.json`、`/api/dns`
- `HO_*` 环境变量：
  - `HO_CONFIG`（`$TRIM_PKGETC`，内含 `domains.json`）、`HO_OUTPUT`、`HO_STATE`
  - `HO_DATA`（用户可见的应用数据目录，FPK 下为共享文件夹 `hosts-optimizer/data`；存放 `admin-token` 与 `logs/app.log`）
  - `HO_PORT`、`HO_TZ`、`HO_CA_BUNDLE`
  - `HO_SCHEDULE_MINUTES`（可选覆盖配置）、`HO_PROBE_DNS`、`HO_PROBE_CONCURRENCY`
  - `HO_DNS_LISTEN`、`HO_DNS_TTL`（应答器监听地址与 TTL；前者接受 off 类词表禁用）
  - `HO_PROBE_TOP_N`、`HO_PROBE_FULL_EVERY`（自适应探测面：常规轮次只测「当前 IP + 前 N 个挑战者」，每 K 轮做一次全量扫描）
  - `HO_WATCH_INTERVAL_SECONDS`、`HO_WATCH_SWITCH_PERCENT`（健康探针：定期只测当前 IP，失效或明显变慢时触发即时轮次，不用等下一个整轮）
  - `HO_EXPAND_CACHE_TTL_HOURS`（子域扩展缓存 TTL，默认 12 小时）
  - `HO_UPDATE_CHECK`（填 `off` 关闭 GitHub 新版本检查）
  - `HO_ADMIN_TOKEN`（管理端点令牌；不设置时首次启动生成并持久化到 `$HO_DATA/admin-token`，重启复用，文件管理器可直接查看；设置后优先于文件）
- 管理端点（`/api/*`、`/refresh`）需要令牌，订阅端点（`/`、`/hosts.txt`、`/agh.txt`、`/status.json`、`/healthz`）保持开放 —— 否则 AGH 拉不到订阅、用户也进不了界面
- 日志：stdout + 内存环（界面「运行日志」）+ `$HO_DATA/logs/app.log`（8MB 轮转，保留 `app.log.1` 一份备份）
- 非 root 运行：**只做 TCP/TLS 探测，不用 ICMP**
- 原子写；整轮校验全灭时保留上一轮结果，绝不写空文件；产物至少含 1 条规则

配置 schema 见 `deploy/config-schema/README.md`，示例见 `domains.example.json`。

## 手动添加域名

安装后编辑共享目录 `/vol1/@appshare/hosts-optimizer/data/domains.json`（文件管理器「应用文件」→ hosts-optimizer → data 可见），在 `domains` 数组追加对象，保存后 `POST /refresh` 即时生效。旧位置 `@appconf` 的配置在升级到 1.4.0+ 时启动自动一次性迁移。

## 冻结轨道 A / B

目录保留但不作为首版交付物。若以后启用，注意：

- 镜像可以是 `FROM scratch` + 单个二进制 + CA 证书，构建本身不需要拉依赖；**但 fnOS Docker 类 FPK 的镜像分发链路仍需平台侧获取镜像**，这是它被降级的原因
- 两份 compose 的 healthcheck 已移除（单二进制镜像内没有 python/curl）
- `.env` 与 compose 的 `HO_SCHEDULE` 已统一改为 `HO_SCHEDULE_MINUTES`，配置统一为 `domains.json`

轨道 A 若单独使用（非 fnOS 设备）：

```bash
cd deploy/compose && cp .env.example .env && cp ../config-schema/domains.example.json ./config/domains.json
sudo docker compose up -d
```

## 核心已接入（`core/`）

`core/` 是 Go 标准库实现的最小原型，链路为：多源 DNS 采集 → 污染/保留 IP 过滤 → TCP 握手测速 → **TLS/SNI 证书链校验** → 滞回防抖与失败不覆盖 → 原子写三份产物 → 单端口 HTTP（`ETag`/304、`POST /refresh`、配置热加载）。详见 `deploy/config-schema/README.md`。

本地开发（无需 NAS）：

```bash
cd core
mkdir -p /tmp/ho-config && cp ../deploy/config-schema/domains.example.json /tmp/ho-config/domains.json
HO_CONFIG=/tmp/ho-config HO_OUTPUT=/tmp/ho-out HO_STATE=/tmp/ho-state HO_PORT=18088 go run ./cmd/hosts-optimizer
# 另开终端
curl http://127.0.0.1:18088/status.json
curl -X POST http://127.0.0.1:18088/refresh
```

`go run ./cmd/hosts-optimizer -check-config` 只校验配置；`go test ./...` 跑离线单元测试。

## 当前状态与剩余工作

完整的「已验证 / 待验证」清单见仓库根 [`README.md`](../README.md)。

**已完成**：`fnpack build` 通过并产出 x86 `.fpk`；真机安装后的无限重启已修复（`cmd/main` 改为 source `cmd/common` + `cmd/service-setup` 并调用 `start_daemon` / `stop_daemon` / `daemon_status`）；桌面入口（`desktop_uidir` + `app/ui/config` + 图标）已补齐；`install_callback` 在真机补回目录执行位；真实公网域名的 TLS 校验与产物生成已验证；页面内在线编辑 `/api/domains` 已实现。

**1.0.1 真机验收**：修复 stop 脚本用 `pkill -f` 误杀自身导致的 `10350`；`app stop` / `app start` / `app restart` 均返回成功且应用中心状态与进程一致；卸载重装后 `domains.json`、`output/`、`state/` 保留；订阅端点 200、`ETag` 304 通过。

**1.0.2 变更**：新增域名发现工具条（输入主域名 → 获取相关子域名 → 勾选 → 添加），表格支持全选与批量删除，页面视觉整体改版；`POST /refresh` 改为后台任务，返回 `202` + `task_id`，页面轮询 `/api/refresh-status` 展示进度。

**1.0.3 变更**：状态表按主域名分组，点分组标题展开该分类并支持整组勾选；配置改为图形化表单（默认参数 + 域名列表 + 单域名高级项），保存后写回 JSON 并触发刷新，保留 JSON 源码模式。

**1.0.4 变更**：`probe_dns` 支持 DoT（`tls://`）与 DoH（`https://`）加密上游，可与 UDP 混用；配置页直接填写并校验。DoQ 需要第三方 QUIC 库，按零依赖约束不支持。

**1.0.5 变更**：新增主题跟随系统与手动切换（浅色/深色/跟随系统）；新增应用内实时运行日志面板（增量拉取、暂停自动刷新、关键字筛选）；发布者与开发者统一为 `wulinwei959`，主页指向 GitHub 仓库。

**1.0.6 变更**：新增探测历史存储（`history/rounds-YYYYMM.jsonl.gz`，按月 gzip 分片，保留期可配置）与历史趋势图；应用图标替换为蓝底地球 + 绿色闪电，1024 源图见 `deploy/icon-source.png`。

**1.0.7 变更**：新增「刷新选中」按钮，支持展开分组后勾选单个域名或整组批量刷新；后端按域名子集探测并合并结果，未选中的域名与产物保持不变。

**1.0.8 变更**：点击延迟单元格可查看本轮全部候选 IP 的延迟并手动切换；「即时刷新」改名「刷新 AGH 规则」，只重写 `agh.txt` 不再重新探测。

**1.0.9 变更**：手动刷新选中域名或手动切换 IP 后自动同步 `agh.txt` 订阅，页面提示同步结果。

**1.0.10 变更**：修复新增域名保存后未出现在域名分组的问题；未探测域名以「待探测」显示，保存后立即出现并可直接刷新。

**1.0.11 变更**：新增域名组与单个域名的禁用选项。禁用后不参与探测、从订阅产物移除，可随时启用；状态表新增「已禁用」筛选。

**1.0.12 变更**：优化「展开域名」弹窗：加宽至 760px、域名与来源同排、IP 单独一行并自动换行，结果列表独立滚动；失败时显示友好提示与「重试」按钮。

**1.0.13 变更**：页面标题、窗口标题与应用名称统一为「Hosts 优选订阅」；优化中文字体栈、字号层级、表格等宽数字，并在页头加入应用图标标识。

**1.0.14 变更**：新增「关于」面板，展示版本号、GitHub 项目地址与使用说明；域名列表整体支持折叠，默认收起，点击标题展开。

**1.1.0 变更**：新增内置 UDP DNS 应答器，AGH 按域名分流直连后，IP 切换最多一个 TTL（默认 60 秒）即可生效；所有配置项补齐图形化入口，并修复长域名与窄屏下的文字重叠。

**1.2.0 变更**：性能与可用性优化——全局并发池、TCP+TLS 握手时延、自适应探测面（当前 IP + Top-N + 周期全量）、健康探针与快速故障转移、历史追加式分片、AGH 分流按长度拆行、DNS 应答器加固；新增管理令牌鉴权（`admin-token` 持久化）与 `/healthz` 健康探针；版本号经 ldflags 注入，`/healthz`、`-version` 与界面三处一致。

**1.3.0 变更**：令牌与日志落到用户可见共享文件夹——`config/resource` 声明 data-share，管理令牌持久化到 `admin-token`（重启复用），运行日志落盘 `logs/app.log`（8MB 轮转）；`HO_DATA` 注入，`/healthz` 含 `data_dir`。

**1.3.1 变更**：修复「禁用本组/单行禁用」后整页重载导致分组自动收起（改原地更新）；按 fnOS 官方 FPK 规范完善：`disable_authorization_path`、启动失败写 `TRIM_TEMP_LOGFILE`、补充升级/卸载向导。

**1.4.0 变更**：子域扩展结果缓存（TTL 12h，手动刷新强制失效）；DNS 应答器支持 TCP（RFC 1035 长度前缀，UDP/TCP 同端口）；`domains.json` 迁移到用户可见共享目录（启动时一次性迁移）；`/refresh` 限流（10s/429）+ GitHub 新版本检查与页面提示。

**1.5.0 变更**：长期运行稳定性——轮次锁改带超时信号量并统一六入口等待策略，整轮 deadline（2~15 分钟自适应）超时作废本轮；扩展缓存定时淘汰 + 配置失效、探针状态与快照按配置裁剪，`/healthz` 暴露轮次/锁/缓存/状态规模观测字段。界面重构：接入方式「DNS 应答器 / AGH 订阅」下拉二选一、切换即时生效；性能档位、切换灵敏度、探测 DNS、状态码白名单改为预设下拉；配置归集四段，管理令牌与检查更新移入「设置与关于」面板（位于页面底部，原独立「关于」卡片移除）。配置瘦身：移除 `suppress_aaaa` / `outputs`，旧键自动忽略。

**仍需**：

1. 确认桌面图标在真机显示（覆盖安装后可能要 `systemctl restart trim_app_center.service`）
2. 观察一周 IP 抖动、滞回表现与 AdGuard Home 长期解析行为
3. 刷新任务状态仅存于进程内存，服务重启后需要重新触发（产物不受影响）
4. 若个别精简版 fnOS 上 `x509.SystemCertPool()` 读不到系统 CA，放一份 `deploy/ca-bundle.crt`，构建脚本会随包携带

## 1.1.0 真机验收

- fnOS x86 应用中心覆盖安装成功，manifest 版本为 `1.1.0`；旧配置、历史与产物保留。
- 正式进程同时监听 `18088` 与 `127.0.0.1:18053`，启动后立即从磁盘恢复上一轮快照。
- 直连 `18053` 查询 `github.com` 返回优选 IP，AAAA 返回 NODATA。
- AGH `/control/dns_config` 写入完整分流规则后，经 53 端口查询 `github.com` 与 `raw.githubusercontent.com` 均返回优选 IP，TTL 为 60 秒。
- AGH 运行配置与 fnOS 应用模板均保存相同分流规则，并保留普通 DNS 兜底，防止应用中心后续重启覆盖。

## 1.5.0 真机验收（192.168.3.59）

- 通过 fnOS 应用中心安装 1.5.0 x86 FPK，版本 1.5.0、运行状态正常，21 个域名配置完整保留，`dns_enabled` 生效。
- 27 项回归 + 压测全过：healthz 观测字段（轮次耗时/超时计数/锁占用/缓存与状态规模）；接入模式双向切换保留域名、页面卡片随模式切换；`/api/update-check` 首次 200、60 秒限流 429；并发刷新 5 路均 202 且任务完成；轮次进行中并发切换返回 409、`round_lock_busy` 递增、超时计数为 0；禁用/启用与刷新后 DNS 应答器实测返回优选 IP；90 秒后规模快照稳定无膨胀。
