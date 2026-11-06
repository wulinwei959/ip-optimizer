# 部署适配层骨架

本目录只解决**部署与分发**，不含业务核心实现。

## 当前取舍：主轨 = fnOS 纯原生 FPK

| 目录 | 形态 | 状态 |
| --- | --- | --- |
| `fnos-native-fpk/` | 纯原生 FPK（单静态二进制 + systemd） | **主轨，首版交付** |
| `compose/` | 通用 Docker Compose | 冻结（可选） |
| `fnos-docker-fpk/` | fnOS Docker 类 FPK | 冻结（可选） |

决策依据：**构建期联网依赖**。Docker 轨要构建并分发镜像，依赖下载链路长；原生 FPK 只需把本机编译好的一个 ELF 放进 `app/bin/`，`fnpack build` 是纯本地文件操作，设备安装阶段完全离线——不拉镜像、不装运行时、不 `pip install`。

**一个必须澄清的点**：原生 FPK ≠ Python 运行时。本骨架初版是 `python312 + venv + pip install`，这条恰好会卡死在依赖下载，已整体移除。飞牛官方 `environment-variables.md` 的 `cmd/main` 示例本身就是 `./myapp --config ... &`；`fnos-apps` 的 Gopeed 原生包 `manifest` 里**没有** `install_dep_apps`，靠自带的 `gopeed` 二进制运行（证据见研究报告第 10 节）。

## 核心工程的技术约束（决定能否真的离线）

- **Go + 仅标准库**：`net/http`（单端口服务）、`crypto/tls`（SNI 证书校验）、`encoding/json`（配置）、`net`（自定义 DNS 查询，可手写 UDP 53 报文或用纯 Go `net.Resolver`）、`time.Ticker`（进程内定时）、`os.Rename`（原子写）。全部标准库，无 `go mod download`。
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
# → deploy/dist/hosts-optimizer-native-1.0.1-x86.fpk / -arm.fpk
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

订阅地址：推荐 `http://<NAS内网IP>:18088/agh.txt`（覆盖子域且 AAAA 天然 NODATA），或 `http://<NAS内网IP>:18088/hosts.txt`。在 AdGuard Home「过滤器 → DNS 封锁清单」添加，更新间隔改为 1 小时。安装后也可从桌面图标打开的状态页一键复制订阅地址。

打包校验要求：`manifest`、`config/privilege`(JSON)、`config/resource`(JSON)、`ICON.PNG`(64×64)、`ICON_256.PNG`(256×256)、`app/`、`cmd/`、`wizard/` 齐全。骨架已生成占位图标，**发布前替换**。

## 核心必须遵守的接口契约

- 单端口 HTTP：FPK 进程/宿主 `18088`（`TRIM_SERVICE_PORT`），Compose 容器内 `8088`
- 路径：`/`、`/hosts.txt`、`/agh.txt`、`/status.json`
- `HO_*` 环境变量：
  - `HO_CONFIG`（`$TRIM_PKGETC`，内含 `domains.json`）、`HO_OUTPUT`、`HO_STATE`
  - `HO_PORT`、`HO_TZ`、`HO_CA_BUNDLE`
  - `HO_SCHEDULE_MINUTES`（可选覆盖配置）、`HO_PROBE_DNS`、`HO_PROBE_CONCURRENCY`
- 非 root 运行：**只做 TCP/TLS 探测，不用 ICMP**
- 原子写；整轮校验全灭时保留上一轮结果，绝不写空文件；产物至少含 1 条规则

配置 schema 见 `deploy/config-schema/README.md`，示例见 `domains.example.json`。

## 手动添加域名

安装后编辑 `/var/apps/hosts-optimizer-native/etc/domains.json`，在 `domains` 数组追加对象。另两种方案（共享目录 / Web 编辑页）见 `config-schema/README.md`，当前骨架未启用。

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

**仍需**：

1. 确认桌面图标在真机显示（覆盖安装后可能要 `systemctl restart trim_app_center.service`）
2. 在真实 AdGuard Home 实例中验证订阅解析与规则生效
3. 用 `curl --resolve` 观察一周 IP 抖动与滞回表现
4. 替换占位图标；用 `uname -m` 确认设备架构、选对安装包
5. `POST /refresh` 当前同步执行，域名多时可能超过客户端超时；后续改为异步任务 + 状态轮询
6. 若个别精简版 fnOS 上 `x509.SystemCertPool()` 读不到系统 CA，放一份 `deploy/ca-bundle.crt`，构建脚本会随包携带
