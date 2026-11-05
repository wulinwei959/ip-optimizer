# 飞牛 fnOS 原生应用适配 + Docker 部署适配方案

- 日期：2026-11-05
- 关联文档：`research/2026-11-05-nas-hosts-ip-optimizer.md`（核心业务方案）
- 本轮交付：`deploy/` 下的部署适配层骨架（**业务核心代码未实现、未在真实 fnOS 设备验证**）

---

## 1. 先纠正一个概念：飞牛的「原生应用」不是独立于 Docker 的另一套东西

飞牛应用中心的安装包统一是 **`.fpk`**（本质是 gzip 压缩的 tar）。所谓「原生」与「Docker」是**同一个 FPK 的两种运行模式**，由 `config/resource` 里的资源声明决定：

| 模式 | `config/resource` 关键字段 | 生命周期由谁管 | `cmd/main` |
| --- | --- | --- | --- |
| Docker 类 FPK | `docker-project: {"projects":[{"name":"...","path":"docker"}]}` | 应用中心执行 `app/docker/docker-compose.yaml` | `start`/`stop` 返回 0 即可，`status` 查容器状态 |
| 纯原生 FPK | `systemd-unit: {}`（**且不得出现 `docker-project`**） | fnOS 以 systemd 服务单元监管 | 需真正管理进程；或用 `cmd/service-setup` 声明服务 |

官方 `docs/core-concepts/resource.md` 只把 `docker-project` 列为「当应用通过 Docker Compose 运行时」使用；真实仓库里 `apps/gopeed/fnos`（原生）的 resource 含 `systemd-unit: {}` 且 `cmd/` 下只有 `service-setup`（无 `main`），而 `apps/immich/fnos`（Docker）含 `docker-project` 且无 `systemd-unit`——两者互斥得到实证。

**所以完整需求其实是三条分发轨道，不是两条**：

```
                       ┌─ A 通用 Docker Compose（任何 NAS / 服务器，SSH 或 Docker GUI）
一套核心程序 ──────────┼─ B fnOS Docker 类 FPK（应用中心安装，内部仍是 compose）
                       └─ C fnOS 纯原生 FPK（不依赖 Docker，systemd + 自带静态二进制）
```

A 与 B 的 compose 可以 **90% 共用**（差别只在配置/产物路径变量与端口注入方式）；C 是真正的第二条技术路线，维护成本明显更高。

---

## 2. 证据（固定 SHA，可复核）

| 结论 | 一手证据 |
| --- | --- |
| FPK 安装后 `/var/apps/{appname}` 下 `target/etc/var/tmp/home/meta` 分别软链到 `/vol{n}/@appcenter|@appconf|@appdata|@apptemp|@apphome`；**必须用 `TRIM_*` 变量，不要硬编码路径** | `ckcoding/fnnas-docs@a8a70503b5b3413f0a00f4b6db6cd62066639508` 的 `docs/core-concepts/framework.md`、`environment-variables.md` |
| `TRIM_APPDEST` / `TRIM_PKGETC` / `TRIM_PKGVAR` / `TRIM_PKGHOME` / `TRIM_SERVICE_PORT` / `TRIM_TEMP_LOGFILE` / `TRIM_USERNAME` 等变量清单 | 同上 `environment-variables.md` |
| `docker-project` 的 `path` **相对于 `app/` 目录**（写 `docker`，不是 `app/docker`）；`name` 为 compose 项目名 | 同上 `resource.md`；另见 `conversun/fnos-apps@6d8f636b401238188ed31f49b331fe48383347fa` 的 `apps/immich/fnos/config/resource` |
| 原生样例：`systemd-unit:{}`、`data-share`、`port-config:{"protocol-file":"Gopeed.sc"}`、`cmd/service-setup` 用 `SVC_BACKGROUND=y` / `SVC_WRITE_PID=y` 声明服务 | 同上 `apps/gopeed/fnos/config/resource`、`cmd/service-setup`、`manifest` |
| `cmd/main` 退出码：`start`/`stop` 成功 0、失败 1；`status` 运行中 0、未运行 3；未知动作 1；失败信息写 `TRIM_TEMP_LOGFILE`；脚本需幂等 | `ckcoding/fnnas-docs` 的 `framework.md`；`kci-lnk/fn-fpk-builder-skill` 的 official-contract.md |
| `config/privilege` 默认 `{"defaults":{"run-as":"package"},"username":"...","groupname":"..."}`；`run-as=root` 不建议且第三方难以发布；需要额外组用 `join-groups` | `ckcoding/fnnas-docs` 的 `privilege.md` |
| 原生 Python 应用：`install_dep_apps=python312`，脚本里 `export PATH=/var/apps/python312/target/bin:$PATH`，依赖放应用目录或专用 venv | `ckcoding/fnnas-docs` 的 `runtime.md` |
| `platform=all` **仅当包内不含特定架构二进制**；`service_port` 单端口；`checkport` 默认 true；`ctl_stop` 控制启停按钮 | `ckcoding/fnnas-docs` 的 `manifest.md` |
| `fnpack` 模板与命令：`create <app> --template docker [--without-ui true]`、`build [--directory]` | 官方 `developer.fnnas.com/docs/cli/fnpack/`；`ckcoding/fnnas-docs` 的 `docs/cli/fnpack.md` |
| `fnpack build` 校验：manifest 存在且含必填字段、`config/privilege` 与 `config/resource` 为合法 JSON、`ICON.PNG`(64×64) 与 `ICON_256.PNG`(256×256) 存在、`app/`、`cmd/`、`wizard/` 目录存在；声明 `desktop_uidir` 时 `app/{desktop_uidir}/` 必须存在 | 官方 fnpack 文档 |
| `fnpack 1.2.3` 提供 **Windows x86 二进制**，本机可直接打包 | 官方 fnpack 下载页 |
| 安装调试：`appcenter-cli install-fpk x.fpk [--env config.env]`、`install-local`、`list/start/stop/default-volume` | 官方 `docs/cli/appcentercli/` |
| 远程安装预检：`fnos-cli app install-fpk <file> --volume-id <id> --dry-run --yes`（写操作须 `--yes`） | 本机 `fnos-cli` 技能 `entries/trim-app.md` |
| Docker 类 FPK 真实工程：`app/docker/docker-compose.yaml` + `cmd/main` 返回 0/3 + `config/resource` 的 `docker-project` | `Gloridust/WechatOnCloud`（`fnos/woc`）；`Mi-Bee-Studio/MiBeeNvr` issue #201；`Gaoyubao0917/douyin-local`（`fnos/douyin-local`，含 `tools/build-fpk.mjs` 自动下载 fnpack） |
| fnOS 环境事实：Debian 12 系；普通用户执行 docker 需 `sudo`；SSH 默认可能未开；Docker 配置常在 `/vol1/1000/docker/<服务名>/` | 本机 `fnos-docker-deploy` 技能（历史实测） |

---

## 3. 硬约束（会直接改变核心程序的设计，必须现在就定）

1. **只监听一个端口。** `manifest.service_port` 是单值，端口入口也只能有一个。管理页、订阅端点、状态接口必须**全部合并到同一个 HTTP 服务**，用路径区分：`/`、`/hosts.txt`、`/agh.txt`、`/status.json`。不要设计成「8088 订阅 + 8089 管理」。
2. **所有路径必须可注入。** FPK 的 `target` 是程序文件目录，`etc` / `var` / `home` 才是持久化位置。核心程序不能写相对路径，必须通过环境变量或参数接收配置目录、产物目录、端口。统一约定 `HO_*` 前缀：
   - `HO_CONFIG`：域名清单所在目录（FPK → `$TRIM_PKGETC`）
   - `HO_OUTPUT`：产物目录（FPK → `$TRIM_PKGVAR/output`）
   - `HO_STATE`：状态/历史目录（FPK → `$TRIM_PKGVAR/state`）
   - `HO_PORT`、`HO_TZ`、`HO_SCHEDULE_MINUTES`、`HO_PROBE_DNS`、`HO_CA_BUNDLE`
3. **非 root 运行 → 不能用 ICMP。** `run-as=package` 无 `cap_net_raw`，`ping` 不可用。这正好与 GitHub520 的 **TCP 443 握手测速**一致，是天然契合，但选型时要明确写死「只做 TCP/TLS 探测」。
4. **绑定高端口。** 应用用户无法绑定 <1024 端口；默认 8088，且在 `wizard/install` 里允许改（避免 `checkport=true` 撞端口）。
5. **`platform=all` 的条件。** 官方 `manifest.md`：可选值 `x86` / `arm` / `all`，`all` **仅当包内不含特定架构二进制**。当前主轨是单静态二进制，因此必须按 `x86` / `arm` 分包；只有纯脚本型应用才能声明 `all`。Docker 类 FPK 要 `all` 则镜像必须提供 amd64 + arm64 manifest。
6. **`version` 与镜像 tag 对齐。** Docker 类 FPK 的 `manifest.version` 建议固定 `X.Y.Z` 且与 compose 里的镜像 tag 一致，否则升级时容易拉到不存在的 tag。
7. **`wizard/` 目录必须存在**（即使内容为空）；向导字段名 → 环境变量，建议 `wizard_` 前缀，别占用 `TRIM_` 命名空间。
8. **生命周期脚本幂等**，失败信息写 `$TRIM_TEMP_LOGFILE` 再返回非零。

---

## 4. 三形态对照与取舍

| 维度 | A 通用 Docker Compose | B fnOS Docker 类 FPK | C fnOS 纯原生 FPK |
| --- | --- | --- | --- |
| 前置依赖 | Docker | Docker + 应用中心 | 无 Docker、无运行时包（自带静态二进制） |
| 安装方式 | `sudo docker compose up -d` 或 fnOS Docker GUI 新建项目 | 应用中心上传 `.fpk` | 应用中心上传 `.fpk` |
| 是否需要 SSH / sudo | 是（fnOS 上） | **否** | 否 |
| 配置目录 | `./config` | `$TRIM_PKGETC` | `$TRIM_PKGETC` |
| 产物目录 | `./output` | `$TRIM_PKGVAR/output` | `$TRIM_PKGVAR/output` |
| 进程守护 | 容器 restart policy | compose + 应用中心 | systemd（`systemd-unit:{}`） |
| 定时任务 | 容器内调度器 | 容器内调度器 | 进程内调度器（不要依赖宿主 crontab） |
| 升级 | 改镜像 tag | 应用中心升级 FPK | 应用中心升级 FPK |
| 桌面入口 | 无 | 可选 `app/ui/config` | 可选 `app/ui/config` |
| 额外维护 | 低 | 低（与 A 共用 compose） | **中**：交叉编译两个架构、PID/日志、CA 证书；无 venv / pip |
| 适用 | 非 fnOS 用户 / CI / 开发 | fnOS 主力用户 | 明确「不装 Docker」的设备 |

**建议（初版，已被第 10 节修订）**：A + B 为第一优先级（几乎同一份 compose，边际成本极低）；C 作为二期，只在明确有「无 Docker 环境」需求时投入。若 C 与 B 同时发布，两个 FPK 的 `appname` 必须不同（如 `hosts-optimizer` 与 `hosts-optimizer-native`），避免应用中心 ID 冲突。

> ⚠️ 本排序只权衡了「维护成本」，**未把「构建期联网依赖」纳入**，在目标网络环境下不成立。第 10 节据此改为 **C 优先、A/B 冻结**；`appname` 不冲突这条规则仍然有效。

**首版一律 `--without-ui true`**：本服务的产出是订阅 URL，用户在 AdGuard Home 里填一次即可，桌面入口收益低却要引入统一网关 / iframe / unix socket 代理等一整套复杂度。等核心稳定后再加 `app/ui/config`。

---

## 5. 推荐的目录结构（本轮已在 `deploy/` 落地骨架）

```
deploy/
├── README.md                       # 构建 / 安装 / 验证命令
├── compose/                        # 轨道 A：通用 Docker
│   ├── docker-compose.yaml
│   └── .env.example
├── fnos-docker-fpk/                # 轨道 B：fnOS Docker 类 FPK 源工程
│   ├── manifest
│   ├── ICON.PNG / ICON_256.PNG     # 占位图标，发布前替换
│   ├── config/privilege            # run-as=package
│   ├── config/resource             # docker-project（关键开关）
│   ├── app/docker/docker-compose.yaml
│   ├── cmd/main                    # status 查容器；start/stop 返回 0
│   ├── cmd/{install,upgrade,uninstall,config}_{init,callback}
│   └── wizard/install              # 端口 / 镜像 tag / 调度周期
├── scripts/build-native-fpk.sh     # ★ 交叉编译 + 按架构分包（本机离线执行）
├── config-schema/                  # domains.example.json + README.md（三形态共享）
└── fnos-native-fpk/                # 轨道 C【主轨】：fnOS 纯原生 FPK 源工程
    ├── manifest                    # 无 install_dep_apps；platform=x86（arm 包由脚本改写）
    ├── config/privilege            # run-as=package
    ├── config/resource             # 仅 systemd-unit:{}（无 docker-project）
    ├── cmd/main                    # status 返回 0/3
    ├── cmd/service-setup           # 直接执行 app/bin/hosts-optimizer
    ├── cmd/install_callback        # 目录 + domains.json + 二进制自检，全离线
    ├── app/bin/hosts-optimizer     # ★ 构建时注入的静态 ELF
    ├── app/ca-bundle.crt           # 可选：CA 兜底
    ├── app/domains.example.json    # 构建时注入的配置模板
    └── wizard/install
```

三套包装层共享同一份 `domains.json` 配置 schema 与同一套 `HO_*` 环境变量，核心程序只有一份；主轨 C 的 `app/bin/hosts-optimizer` 由 `scripts/build-native-fpk.sh` 在构建机交叉编译后注入，不在源码树里维护。

---

## 6. 构建与验证命令

**打包（本机 Windows 即可，fnpack 1.2.3 提供 windows-amd64）**

```bash
# 下载 fnpack-1.2.3-windows-amd64 后重命名为 fnpack.exe 并加入 PATH
fnpack create hosts-optimizer --template docker --without-ui true   # 生成模板参考
fnpack build --directory deploy/fnos-docker-fpk                     # 产出 hosts-optimizer-*.fpk
fnpack build --directory deploy/fnos-native-fpk
```

> `fnpack build` 会校验 manifest / privilege(JSON) / resource(JSON) / 两个图标 / `app/` / `cmd/` / `wizard/`。`wizard/` 为空目录也要存在。构建前清理 `.DS_Store` 等杂项文件。

**安装到测试设备（推荐用专门测试机，不要在生产 NAS 上反复装卸）**

```
应用中心 → 右上角菜单 → 安装本地应用 → 选择 .fpk
```

或在 fnOS 设备上：

```bash
appcenter-cli default-volume
appcenter-cli install-fpk hosts-optimizer-1.0.0.fpk --env config.env
appcenter-cli list
appcenter-cli start hosts-optimizer
```

从本机远程预检（只读 `dry-run`，写操作才加 `--yes`）：

```bash
fnos-cli app install-fpk hosts-optimizer-1.0.0.fpk --volume-id 1 --dry-run --yes
```

**轨道 A 在 fnOS 上的注意事项**：普通用户执行 docker 需 `sudo`；若走 SSH，先确认「设置 → 终端」已开启；Compose 项目放 `/vol1/1000/docker/hosts-optimizer/`。**用 FPK 则完全绕开 SSH 与 sudo**，这是 B 相对 A 的实际收益。

**验收清单（发布前逐项）**
1. 首次安装 → `appcenter-cli list` 显示运行中；`curl http://<NAS_IP>:<port>/status.json` 返回 200
2. 启动 / 停止 / 重启 / 卸载后重装 / 升级到新版本，配置与产物不丢（`TRIM_PKGVAR` 持久化生效）
3. 在 AdGuard Home 添加 `http://<NAS_IP>:<port>/hosts.txt` 到 **DNS 封锁清单**，`dig @<AGH_IP> <域名>` 返回优选 IP
4. 故意让全部候选 IP 校验失败 → 服务端保留上一轮 hosts，且 AGH 列表规则数仍 > 0
5. 端口冲突（安装时已占用）→ `checkport` 给出清晰错误，`$TRIM_TEMP_LOGFILE` 有可执行提示
6. 原生轨道额外验证：静态 ELF 与设备架构匹配、`CGO_ENABLED=0` 产物能在 fnOS 直接执行、随包 CA / 系统证书池能完成 TLS 校验、进程以包用户运行、无 ICMP 权限时测速仍正常
7. `platform=all` 时分别在 x86 与 ARM 设备实测

---

## 7. 容易踩的坑（fnOS 特有）

- **`docker-project` 的 `path` 是相对 `app/` 的**，`"docker"` 对应 `app/docker/docker-compose.yaml`；写成 `app/docker` 应用中心找不到 compose。
- **compose 项目名 `name` 必须符合 Docker 命名规则**（小写字母/数字/`-`/`_`，以小写字母或数字开头）。
- **原生 FPK 千万别带 `docker-project`**，否则平台改用容器编排，`cmd/main` 与 systemd 都不生效；反之 Docker FPK 别写 `systemd-unit`。
- 别在 `target`（`$TRIM_APPDEST`）里写运行时数据，那是程序文件目录；只写 `TRIM_PKGVAR` / `TRIM_PKGHOME`。
- 原生样例里的 `port-config: {"protocol-file":"Xxx.sc"}` 与 `health.json` 在真实仓库普遍存在（防火墙端口规则、健康检查），但官方文档未在 `resource.md` 正文列出 `port-config`；**首版先不依赖它，实测确认设备版本支持后再加**。
- Docker 类 FPK 若把 `/var/run/docker.sock` 挂进容器，等价于宿主 root 权限，且与 `run-as=package` 可能冲突。本服务**不需要** docker.sock（应用中心自己执行 compose），别画蛇添足。
- 探针容器/进程的 DNS 要显式指定外部 DNS，绕开 AdGuard Home；订阅 URL 用 NAS 内网 IP——这两条循环依赖见核心方案文档第 5 节，FPK 环境同样成立。
- 官方建议用**专用测试设备**反复装卸，不要在存放重要数据的 NAS 上做开发测试。

---

## 8. 验证层级与未验证范围

| 结论 | 层级 |
| --- | --- |
| FPK 包结构、manifest 字段、`TRIM_*` 变量、`docker-project` / `systemd-unit` 语义、privilege/resource JSON、fnpack 校验规则、appcenter-cli 命令 | **1 源码/官方文档核查**（固定 SHA 见第 2 节） |
| `Gopeed`（原生）/ `Immich`（Docker）/ `WechatOnCloud`（Docker）真实工程的配置 | **1 源码核查** |
| 本轮生成的骨架能否通过 `fnpack build`、能否在真实 fnOS 安装运行、systemd 模式行为、端口规则生效 | **4 待验证** —— 本机未安装 fnpack，未在 fnOS 设备上实测 |

**不要把这些骨架当成已验证的适配**：它们是按官方契约写出的起点，必须在测试设备上跑通第 6 节验收清单才算完成。

---

## 9. 实施顺序（已按第 10 节修订）

1. 定死核心接口契约：单端口 HTTP、`HO_*` 环境变量、`domains.json` schema、产物三件套。**这个契约定死之前不要写任何包装层**，否则三种形态会各自漂移。
2. 用 Go 标准库实现核心最小原型（多源 DNS 采集 + TLS/SNI 校验 + 生成 `hosts.txt`），用 `curl --resolve` 手工核对校验器确实能淘汰错误 IP。
3. 跑 `SKIP_PACK=1 ./deploy/scripts/build-native-fpk.sh x86`，确认 `GOPROXY=off` 下能编译出静态 ELF。
4. 产出 x86 / arm 两个 `.fpk`，在专用 fnOS 测试设备跑第 6 节验收清单。
5. A / B 保持冻结；确需时再以 `FROM scratch` 单二进制镜像低成本启用。
6. 三期才考虑桌面入口、共享目录配置编辑、开放 API、应用中心上架。

---

## 10. 【修订】离线构建约束下的决策修正（2026-11-05）

### 10.1 新约束

用户补充：目标网络环境下 Docker 镜像构建与依赖下载成本高、很多依赖拉不下来。于是「**构建期是否需要联网**」上升为第一约束，覆盖第 4 节以「维护成本」为主的排序。

结论：**C（纯原生 FPK）提升为主轨，A / B 冻结为可选**，`deploy/` 骨架已按此重构。

### 10.2 关键修正：原生 FPK 若用 Python，一样会卡在依赖下载

初版 C 方案是 `install_dep_apps=python312` + `cmd/install_callback` 里 `python3 -m venv` + `pip install -r requirements.txt`。这条只是把联网从 NAS 挪到构建机，**没有消除联网依赖**，而且 `python312` 运行时包本身也要从飞牛应用中心获取。所以「选原生」并不自动等于「离线」——必须同时换掉实现语言与运行时模型，用户的方向判断才真正落地。

### 10.3 一手证据：自带二进制才是原生 FPK 的标准形态

| 证据 | 内容 | 来源 |
| --- | --- | --- |
| 官方 `cmd/main` 示例直接执行二进制 | `./myapp --config "$TRIM_PKGETC/config.conf" --data ... &`，无 venv、无 PATH 注入 | `ckcoding/fnnas-docs@a8a70503b5b3413f0a00f4b6db6cd62066639508` 的 `docs/core-concepts/environment-variables.md` |
| `install_dep_apps` 是可选能力 | `runtime.md` 措辞为「应用**可以**使用 Python、Node.js 或 Java 等打包运行时环境」；官方 manifest 示例里没有该字段 | 同仓库 `runtime.md` / `manifest.md` |
| `platform` 取值与 `all` 的限制 | 可选 `x86` / `arm` / `all`；`all` **仅当应用包不包含特定架构二进制** | 同仓库 `manifest.md` |
| Gopeed 原生 FPK 无运行时依赖 | `manifest` 里没有 `install_dep_apps`，`platform=x86`；`cmd/service-setup` 的 `SERVICE_COMMAND="$APP_DIR/bin/gopeed-server $APP_DATA_DIR"`；`bin/gopeed-server` 是 186B wrapper，`exec ./gopeed` | `conversun/fnos-apps@6d8f636b401238188ed31f49b331fe48383347fa` 的 `apps/gopeed/fnos/` |
| 构建机准备二进制、随包分发 | `update_gopeed.sh --arch x86\|arm` 下载对应架构 zip，解压出 ELF 放进 `app_root/gopeed`，用户安装时完全离线 | 同仓库 `apps/gopeed/update_gopeed.sh` |
| `config/resource` 只声明实际需要的资源 | 「这个文件应只包含应用实际使用的能力」；`data-share` 只在需要用户文件访问时声明 | 同仓库 `resource.md` |

Gopeed 已经证明「构建机联网准备二进制 → FPK 内含二进制 → 设备安装离线」这条链路成立。本项目可再进一步：**自己用 Go 标准库从源码编译**，连构建机的模块下载也省掉。

### 10.4 修正后的技术方案

- **核心：Go，仅标准库**。`net/http`（单端口服务）、`crypto/tls`（SNI 证书校验）、`encoding/json`（配置）、`net`（自定义 DNS 查询，可用纯 Go `net.Resolver` 或手写 UDP 53 报文）、`time.Ticker`（进程内定时）、`os.Rename`（原子写）覆盖全部需求。
- **构建**：`CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64 GOPROXY=off GOSUMDB=off go build -trimpath -ldflags="-s -w"`。在 Windows 上交叉编译出 Linux 静态 ELF，不需要 Linux 机器、Docker daemon、基础镜像；`GOPROXY=off` 用于强制校验「确实零第三方依赖」。
- **唯一一次性联网**：本机安装 Go SDK（单个安装包）。之后全部离线；`fnpack build` 只是本地 tar/gzip 操作。
- **配置格式 YAML → JSON**：YAML 需要 `gopkg.in/yaml.v3` 等第三方模块，会引入 `go mod download`。调度由 cron 表达式改为 `schedule_minutes`（整数分钟，进程内定时），顺带修掉「cron 值含空格、被 `source settings.env` 拆词执行」的隐藏 bug。
- **CA 根证书**：静态二进制不自带系统信任库；优先 `x509.SystemCertPool()`（fnOS 为 Debian 系），失败回落随包 `ca-bundle.crt`，通过 `HO_CA_BUNDLE` 注入。
- **按架构分包**：`platform=x86` / `arm` 两个 `.fpk`，`build-native-fpk.sh` 自动改 manifest 并产出；不再使用 `platform=all`。

### 10.5 依赖下载点对比（修订理由）

| 环节 | 初版 A/B（镜像） | 初版 C（Python 原生） | 修订后 C（Go 单二进制） |
| --- | --- | --- | --- |
| 构建机 | 基础镜像 + 语言依赖 + 镜像 push | Python wheel / venv | Go SDK（一次性） |
| 分发介质 | registry 镜像 | FPK + 运行时包 `python312` | FPK（内含单个 ELF） |
| 设备安装 | 拉镜像 | 装运行时 + `pip install`（**需联网**） | 无下载 |
| 失败面 | 大 | 中 | 极小 |

> 补充：单二进制下 Docker 镜像其实可以 `FROM scratch`，构建成本也趋近于零；但 fnOS Docker 类 FPK 仍走平台侧镜像获取链路，**在本约束下依旧不如原生稳**，故维持冻结。用户「编译镜像成本高」的判断在 Python/多依赖实现下完全成立。

### 10.6 骨架改动清单（本轮已落地）

- `fnos-native-fpk/manifest`：删 `install_dep_apps=python312`，`platform=all` → `x86`
- `config/resource`：精简为 `{"systemd-unit": {}}`（去掉不需要的 `data-share`）
- `cmd/service-setup`：直接执行 `$TRIM_APPDEST/bin/hosts-optimizer`，去掉 venv / PATH / PYTHONPATH
- `cmd/install_callback`：去掉 venv + pip，改为「目录初始化 + `domains.json` + 二进制自检」，不再写 `settings.env`
- `cmd/main`：进程名匹配改为 `hosts-optimizer`
- `wizard/install`：去掉「需 python312」「首次安装需联网」提示
- 删除 `app/src/`（Python 核心位）与 `domains.example.yaml`；新增 `app/bin/README.md`、`config-schema/domains.example.json`、`config-schema/README.md`、`scripts/build-native-fpk.sh`
- 两份 compose 与 `.env.example`：`HO_SCHEDULE` → `HO_SCHEDULE_MINUTES`、配置统一 `domains.json`、移除依赖 python/curl 的 healthcheck
- `deploy/README.md`：主轨改为 C，A / B 标注冻结

### 10.7 验证状态（核心实现后更新，2026-11-05）

**已在本机验证**（便携 Go 1.23.4，装在临时目录、未进项目）：

- `go list -m all` 只有本模块 → **零第三方依赖**成立；全程 `GOPROXY=off GOSUMDB=off`
- `go vet ./...` 通过；`go test ./...` 4 个包全通过：DNS 报文/压缩指针解析、污染 IP 过滤、TLS 正例与三类反例（错误 SNI、不可信 CA、非 TLS 端口）、滞回 6 种情形、产物生成
- `CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64` 交叉编译成功；ELF `e_machine` 分别为 `0x3e` / `0xb7`，`go version -m` 显示 `CGO_ENABLED=0`
- `build-native-fpk.sh` 以 `SKIP_PACK=1` 实跑 x86 / arm，编译与 `manifest.platform` 改写均通过
- 端到端（本机起服务）：`/status.json` 200、`ETag` 条件请求 304、`POST /refresh` 200、首页 200、三份产物与状态文件落盘；失败路径 `hosts.txt` 返回 503 且保留上一轮结果
- 成功路径（本地自签 TLS 服务 + `HO_CA_BUNDLE`）：产出 `127.0.0.1 good.test` 与 `||good.test^$dnsrewrite=NOERROR;A;127.0.0.1`，`ready=true`

**仍未验证**：

- `fnpack build` 未运行（本机未装 fnpack），**未产出 `.fpk`**
- 未在真实 fnOS 设备安装；`systemd-unit` 下 `SVC_BACKGROUND` / `SVC_WRITE_PID` 行为、`TRIM_SERVICE_PORT` 是否在 `service-setup` 阶段注入，需真机验证
- `x509.SystemCertPool()` 在目标 fnOS 版本能否读到系统 CA 未验证；随包 `ca-bundle.crt` 是兜底
- `TRIM_DATA_SHARE_PATHS` 注入时序未验证，共享目录编辑方案暂未启用
- **真实公网域名**下的 TLS 校验命中率、多源 DNS 并集质量、IP 抖动与滞回表现均未实测（本机 E2E 用的是本地自签 TLS 服务）

### 10.8 附：一条会静默失效的规则（源码核查）

初版方案写过 `||domain^$dnsrewrite=NOERROR;AAAA;` 来抑制 IPv6。核查后确认这是**非法规则**：

| 证据 | 内容 | 来源 |
| --- | --- | --- |
| `parseDNSRewrite` 用 `SplitN(s, ";", 3)`，只给两段会报 `expected zero or two delimiters` | 全形式必须是三段 | `AdguardTeam/urlfilter@347285f3f046958ed97d0fcf58da20b1b49be101` 的 `rules/dnsrewrite.go` |
| `dnsRewriteRRHandlers[dns.TypeAAAA]` 要求 `netutil.IsValidIPString(valStr)` 且 `ip.Is6()` | 空 VALUE 会报 `is not a valid ipv6` | 同上 |
| `loadDNSRewriteNormal` 仅当 `rrStr == "" && valStr == ""` 时返回纯 RCODE 重写 | 该写法不区分记录类型，不能只清 AAAA | 同上 |
| 官方测试用例只有 `noerror;aaaa;::1`，没有空值样例 | 佐证空值不受支持 | 同仓库 `rules/dnsrewrite_test.go` |
| 官方 wiki：`dnsrewrite` 替换整个应答，应答只含与查询类型匹配的 RR；「responses to some requests may become empty (NODATA)」 | AAAA 查询自动返回空 NOERROR | `AdguardTeam/AdGuardHome` wiki `Hosts-Blocklists`；`adguard-dns.io/kb/.../dns-filtering-syntax/` |

结论：`agh.txt` 只输出 `||domain^$dnsrewrite=NOERROR;A;IP`，**不输出任何 AAAA 规则**；IPv6 抑制靠 dnsrewrite 的 NODATA 特性。订阅 `hosts.txt` 时 AAAA 仍可能绕过，因此推荐 AGH 优先订阅 `agh.txt`。字段说明见 `deploy/config-schema/README.md`。
