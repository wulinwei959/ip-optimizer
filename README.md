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

---

## 工作原理

```
domains.json
   ↓ 多源 DNS 采集（手写 UDP 53 报文，无第三方库）
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

两条防循环依赖的硬约束：

- `probe_dns` 必须是**字面 IP**（配置校验会拒绝主机名），且必须绕开本机 AdGuard Home —— 否则「用待优化的解析结果去找候选 IP」形成循环依赖。
- 订阅地址用 NAS **内网 IP**，不要填公网域名。

核心用 **Go 标准库、零第三方依赖**（`go.mod` 仅 `module hosts-optimizer` + `go 1.21`），`CGO_ENABLED=0` 交叉编译成单个静态 ELF。构建脚本强制 `GOPROXY=off`：一旦误引入第三方依赖会直接构建失败，而不是偷偷联网。

---

## 特性

- **离线**：唯一一次性联网是安装 Go SDK；之后构建与 fnOS 设备安装全程离线，不拉镜像、不装运行时、不 `pip install`。
- **非 root 安全**：`run-as=package`，只做 TCP/TLS 探测（不用 ICMP，因无 `cap_net_raw`），仅监听一个高端口。
- **失败不覆盖**：整轮校验全灭时保留上一轮产物，`hosts.txt` / `agh.txt` 返回 503 但绝不写空列表；`status.json` 仍为 200 并说明原因。
- **配置热加载**：每轮重新读取 `domains.json`，增删域名下一轮自动生效；也可 `POST /refresh` 立即重跑，无需重启。
- **重启可恢复**：启动时从磁盘恢复上一轮产物，不必等首轮探测结束就能对外提供订阅。
- **fnOS 桌面入口**：桌面图标以 iframe 窗口打开状态页，可查看生效 IP / 延迟、一键复制订阅地址、点「立即刷新」触发新一轮。

---

## 快速开始

### 路线 1：fnOS 真机（主轨，推荐）

1. **确认架构**：`uname -m` → `x86_64` 用 x86 包，`aarch64` 用 arm 包。`platform=all` 不可用（官方规定包内含架构专属二进制时必须分包）。
2. **获取安装包**：`.fpk` 二进制产物不入库（见 `.gitignore`），需本地构建（见下节）或从 Releases 下载（若已发布）。
3. **安装**：应用中心 → 右上角菜单 → 安装本地应用 → 选择 `.fpk`。安装完全离线。
4. **打开桌面图标**：若覆盖安装后图标未出现，在 NAS 上执行 `systemctl restart trim_app_center.service` 再刷新桌面。
5. **配置 AdGuard Home**：在「过滤器 → DNS 封锁清单」添加订阅地址，更新间隔设为 1 小时。

   ```
   http://<NAS内网IP>:18088/agh.txt     # 推荐
   http://<NAS内网IP>:18088/hosts.txt   # /etc/hosts 语法，精确匹配、不覆盖子域
   ```

   `agh.txt` 使用 `||domain^$dnsrewrite=NOERROR;A;IP`，覆盖子域且让 AAAA 天然返回 NODATA（详见下方「已查证的坑」）。
6. **添加域名**：打开状态页，在「编辑域名清单」中修改并点「保存并生效」；也可直接编辑 `/var/apps/hosts-optimizer-native/etc/domains.json`。

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
| `HO_CONFIG` | `.` | 配置**目录**，内含 `domains.json`；FPK 注入 `$TRIM_PKGETC` |
| `HO_OUTPUT` | `./output` | 产物目录；FPK 注入 `$TRIM_PKGVAR/output` |
| `HO_STATE` | `./state` | 状态/历史目录；FPK 注入 `$TRIM_PKGVAR/state` |
| `HO_PORT` | `8088` | 监听端口；FPK 注入 `$TRIM_SERVICE_PORT`（`18088`） |
| `HO_TZ` | `Asia/Shanghai` | 时区，静态二进制自带 tzdata，不依赖宿主 `/usr/share/zoneinfo` |
| `HO_CA_BUNDLE` | 空 | 可选 CA 证书文件；**文件不存在时降级为仅用系统证书池，不是致命错误** |
| `HO_SCHEDULE_MINUTES` | — | 覆盖 `defaults.schedule_minutes` |
| `HO_PROBE_DNS` | — | 覆盖上游 DNS，逗号分隔的字面 IP |
| `HO_PROBE_CONCURRENCY` | — | 覆盖 `defaults.concurrency` |

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

`domains[]` 还支持 `candidates`（固定候选 IP 池）、`expect_status`（在 TLS 连接上校验 HTTP 状态码，默认关闭）、`allow_private`、`suppress_aaaa`。完整字段表、取值范围与校验规则见 [`deploy/config-schema/README.md`](deploy/config-schema/README.md)，示例见 [`deploy/config-schema/domains.example.json`](deploy/config-schema/domains.example.json)。

> 用 JSON 而非 YAML，是为了不引入 `go mod download`。

### HTTP 端点（单端口）

| 路径 | 说明 |
| --- | --- |
| `/` | 概览页：状态表格、复制订阅地址、立即刷新 |
| `/hosts.txt` | `IP domain` 逐行，`/etc/hosts` 语法 |
| `/agh.txt` | `\|\|domain^$dnsrewrite=NOERROR;A;IP`，推荐 |
| `/status.json` | 每域名候选数、通过数、生效 IP、延迟、切换原因、本轮时间 |
| `POST /refresh` | 立即重跑一轮，返回 `{"ok":true,"next_round_minutes":N}` |

文本端点返回 `ETag` / `Last-Modified`，支持 `If-None-Match` → 304。

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
│   └── internal/{config,dnsquery,probe,store,output,app,util}
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
- 本机端到端：`/status.json` 200、`ETag` → 304、`POST /refresh` 200、三份产物落盘；失败路径保留上一轮结果且 `hosts.txt` 返回 503。
- `fnpack build` 通过并产出 x86 `.fpk`；包结构、manifest 字段与桌面入口文件已解包核对。
- **真机 1.0.0**：二进制以包用户（uid 900）运行可监听、抓取、写产物，SIGTERM 干净退出；`github.com` / `raw.githubusercontent.com` 的 TLS 校验通过并产出真实 IP；无限重启问题已修复。
- **真机 1.0.1**：`app stop` / `app start` / `app restart` 均返回成功，应用中心状态与真实进程一致；卸载重装后 `domains.json`、`output/`、`state/` 保留；`/`、`/status.json`、`/hosts.txt`、`/agh.txt` 均返回 200，`ETag` → 304；`10350` 已修复。

**待验证 / 已知限制**

- 桌面图标入口（本轮新补）的真机显示效果尚未确认；覆盖安装后可能需要重启 `trim_app_center.service`。
- 尚未在真实 AdGuard Home 实例中验证订阅解析与规则生效；当前只验证了订阅端点内容与 HTTP 语义。
- 真实公网域名下的一周 IP 抖动、滞回表现与多源 DNS 并集质量未长期观测。
- `POST /refresh` 是同步接口：域名较多且候选超时时，单轮可能超过 50 秒；若同时撞上定时轮次，客户端可能等待超过 90 秒。后续可改为异步任务 + 状态轮询。
- 图标是占位图（尺寸合规但很素），发布前建议替换。
- A / B 轨道未验证；`config/resource` 的 `data-share` 共享目录编辑方案未启用。
- `x509.SystemCertPool()` 在个别精简 fnOS 版本可能读不到系统 CA，此时需随包 `ca-bundle.crt`。

首次安装、启停重启、卸载重装、配置与产物保留、全灭时保留上一轮均已在真机验证；发布前还需补做真实 AdGuard Home 订阅接入与解析验证。

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
