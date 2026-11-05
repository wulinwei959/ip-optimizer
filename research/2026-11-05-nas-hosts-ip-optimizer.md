# NAS 自建「域名 → 优选 IP → hosts 订阅」服务：开源复用调研与方案意见

- 调研日期：2026-11-05
- 需求：在 NAS 上部署一个服务；手动维护域名清单；定时刷新"最优 IP"；生成 hosts 文件 URL 供 AdGuard Home 作为过滤规则订阅；形态类似 GitHub520。
- 范围：只做调研与方案判断，**未部署、未运行、未实测**。所有结论的证据层级见文末。
- 检索方式：`gh` CLI 2.96.0（已登录 `wulinwei959`）、GitHub REST API、`WebSearch` / `WebFetch`。

---

## 1. 先给结论

**值得做，但要把定位收窄成"自家一小撮域名的私有 hosts 订阅生成器"，而不是"通用域名加速器"。**

1. **链路可行性已被官方与现成项目双重验证，不需要重新发明。** AdGuard Home 官方 wiki 明确：`1.2.3.4 example.org` 这种 `/etc/hosts` 语法会用该 IP 应答该域名的 DNS 查询。GitHub520 的 README 第 2.4 节直接给出了 AdGuard Home 的订阅配置方法。所以"生成 hosts URL → AGH 订阅"这一段是通的。
2. **难点不在测速，在"泛化"本身。** GitHub520 敢只做 TCP 443 三次取中位数就发 hosts，是因为它的 40 个域名全是 GitHub 自有资产、IP 归属明确、证书覆盖。一旦允许手动添加任意域名，"最快 IP"很容易变成"错误 IP"。项目真正的工程量应放在**候选 IP 的合法性校验、防呆、失败不覆盖**上。
3. **没有成熟的通用自托管轮子可直接用。** 找到的最接近项目都是小体量、且各自限定在 Cloudflare IP 段或 Cloudflare Workers 上；但其中有一份 MIT 许可的 Docker 工程骨架非常值得借鉴（见第 3 节）。
4. **有一条零代码的替代路线**：SmartDNS 作为 AdGuard Home 的上游，用 `speed-check-mode ping,tcp:80,tcp:443` + `response-mode fastest-ip` 实时选最快 IP。若你不需要"可分享的订阅链接 / 多实例复用 / 历史记录"，这条更划算。

---

## 2. 项目基线（当前是想法阶段，工作区无代码）

| 项 | 内容 |
| --- | --- |
| 现状 | 无现有实现、无仓库、无技术栈约束 |
| 目标平台 | NAS（Docker）；用户此前有 fnOS 设备与 Docker 部署经验 |
| 输入 | 人工维护的域名清单 |
| 输出 | 一个 HTTP 可达的 hosts 格式文本，被 AdGuard Home 以自定义过滤列表订阅 |
| 隐含约束 | 测速视角必须是"这台 NAS 所在宽带"，不是云端 CDN 视角；服务需长期常驻、失败不能污染全网 DNS |

主要数据流与高价值缺口：

> 域名清单 → 候选 IP 采集 → 探测评分 → 生成文件 → 静态 HTTP → AGH 拉取 → 客户端 DNS 缓存

其中"探测评分"最容易被高估，"合法性校验""失败回退""AGH 侧缓存/匹配语义"最容易被漏掉。

---

## 3. 候选对照（按推荐度排序）

| 仓库 | Star / 最近推送 / 许可 | 具体可借鉴内容 | 适配判断 | 采用决定 |
| --- | --- | --- | --- | --- |
| `LancelotRar/self-hosted-best-cf-ip-scanner` | 7★ / 2026-11-02 / **MIT** | Dockerfile + `compose.example.yaml` + `.env` 全参数化、cron 调度、`scan-once` 手动轮次、防并发锁、**任一阶段全灭则非零退出且不写新产物（失败不覆盖）**、原子写、非 root + 只读根文件系统、`doctor.sh` 自检、启动打印生效配置、订阅列表发布 | 工程骨架与本项目几乎同构，且许可宽松、代码活跃。但它测的是 Cloudflare IP 段、产出的是优选 IP 列表而非 hosts，探测对象是 TCP 握手 + `/cdn-cgi/trace` 边缘校验 | **强烈建议借鉴设计**（层级 1），不直接采用 |
| `XIU2/CloudflareSpeedTest` | 29.8k★ / 2026-09-15 / **GPL-3.0** | TCPing / HTTPing、丢包率分档排序、`-url` 绑定域名做 TLS 证书校验、证书不匹配直接 `0.00`、明确警告"测速必须关闭代理"、HTTPing 高并发等同网络扫描 | 算法与运维经验值得借鉴；但无库 API，只有 CLI + `result.csv`，`result.csv` 中文表头、可能有交互式"按回车退出"，绑定 Cloudflare 下载测速地址；GPL-3.0 且不适合作为库嵌入 | **只借鉴思路**（层级 1），不集成 |
| `TinsFox/github-hosts` | 219★ / 2026-02-03 / **MIT** | Workers + 多公共 DNS、每 60 分钟更新、`GET /hosts`、`GET /hosts.json`、`GET /{domain}`、`POST /reset` 的 API 形态 | 产物与 API 设计可参考；但固定 GitHub 域名、跑在 Workers 上（测速视角是云端不是家宽），且 README 顶部公告"服务已临时下线——因接口被刷，KV 配额已耗尽"。这恰好说明**公开订阅会被刷，内网自建反而规避了该风险** | **借鉴产物格式**（层级 1），不采用 |
| `Yan-nian/custom-hosts-optimizer` | 17★ / 2025-06-25 / **MIT** | 最接近想法：自定义任意域名、Web 管理界面、REST API、KV 持久化、每小时更新；上游注明参考 GitHub520 与 `TinsFox/github-hosts` | 部署目标是 Cloudflare Workers 而非 NAS；README 自述"AI 魔改"、仓库含 `deploy_broken.yml.bak`、`OPTIMIZE_FIX_REPORT.md` 等痕迹，近一年半未更新，Star 很低。探测发生在 Workers 边缘，与"家宽视角"不符 | **不采用**，仅作为"有人试过"的佐证（层级 1） |
| `521xueweihan/GitHub520` | 30.1k★ / 2026-11-05 / **CC BY-NC-ND 4.0**（GitHub API `license: null`，README 底部声明） | 多源 DNS（3 个 DoH + 5 个传统 DNS）取并集 → 剔保留地址 → TCP 443 连 3 次取中位数 → 选最快；内容无变化不写；GitHub Actions `cron: '0 */2 * * *'` 每 2 小时；产物 `hosts` + `hosts.json` | 算法思路正是需求原型，域名清单硬编码在 `common.py`（40 个），不可配置；**许可含"禁止演绎"(ND) 且非商业，fork 改代码再分发有法律风险** | **只借鉴算法思路并重写，不复制代码**（层级 1） |
| `pboymt/Steam520` | 115★ / 2025-04-15 / GPL-3.0 | 把 GitHub520 泛化到另一组域名（Steam），TypeScript + Actions 生成 hosts/hosts.json，README 同样写了 AdGuard Home 订阅方式 | 证明"换一组域名即可复用同一套流水线"，但仍是固定清单；当前 hosts 内容已为空 | 参考（层级 1） |
| `pymumu/smartdns` | 11.3k★ / 2026-11-05 / GPL-3.0 | `speed-check-mode ping,tcp:80,tcp:443`、`response-mode fastest-ip` / `first-ping`、`max-reply-ip-num`、`domain-rules /x.com/ -speed-check-mode ...`、缓存 | 零代码实现"实时返回最快 IP"，把它作为 AGH 上游即可；**但没有订阅 URL、结果不持久化、无法跨实例分享** | **替代路线**，不作为本项目组件（层级 1） |
| `217heidai/NestingDNS` | 366★ / 2026-10-29 / GPL-3.0 | AGH → MosDNS → SmartDNS 三层套娃；默认关闭 IPv6；CDN IP 优选默认关闭且注释写明"测速必须关闭代理，因此未做成自动化脚本，请定期手工测速" | 印证两件事：测速与代理出口必须分离、以及"自动优选"在真实套件里确实还没被解决 | 参考（层级 1） |
| `ZhiXuanWang/cf-speed-dns` | 1593★ / 2026-11-05 | Actions 每 5 分钟跑 CFST，把最优 IP 推送到 DNSPod / Cloudflare DNS 记录，输出 `ipTop.html` 纯文本列表 | 是"定时优选 → 落地解析"的成熟范例，但落点是权威 DNS 不是 hosts 订阅，且限定 Cloudflare | 参考（层级 1） |

**中小项目检索结果**（说明这个位置确实没有成熟方案）：`chenfangshuo/Cloudflare-Hosts-Optimizer`(2★)、`hexo2020/cf-speed`(0★)、`koljs/gh-hosts-updater`(1★)、`taolei05/NetOptim`(1★) 等，全部聚焦 Cloudflare 或 GitHub、Star 个位数、无持续维护。

---

## 4. 固定源码证据（可复核）

| 结论 | 固定证据 |
| --- | --- |
| GitHub520 用 3 次 TCP 443 取中位数，1s 超时；DoH 为阿里/DNSPod/Google，传统 DNS 为 114/阿里/腾讯/Cloudflare/Google；剔除 `1.0.1.1`、`1.2.1.1`、`127.0.0.1` | `521xueweihan/GitHub520@7db0e1b0316408ef0f1a750aebf80730bb175357` 的 `fetch_ips.py`（`ping_cached` / `select_ip_from_list` / `DOH_SERVERS` / `DNS_SERVER_LIST`） |
| 域名清单硬编码 40 个，hosts 模板 `HOSTS_TEMPLATE`，`write_hosts_content` 有变化才写 | 同 SHA 的 `common.py`、`update_ips.py` |
| 每 2 小时跑一次 | 同 SHA 的 `.github/workflows/GitHub520.yml`：`cron: '0 */2 * * *'` |
| AGH 的 hosts 语法用该 IP 应答、**不覆盖子域**；`0.0.0.0`/`127.0.0.1` 视为拦截；`$dnsrewrite=NOERROR;A;1.2.3.4` 可显式指定 A 记录且优先级更高 | `AdguardTeam/AdGuardHome` Wiki `Hosts-Blocklists`；当前 master SHA `13a429f0e4d1b011ef2a902c93dd394deca19d24` 的 `internal/filtering/http.go` |
| AGH 过滤列表：默认更新间隔 **24 小时**；添加/更新时**校验至少含一条规则**；用 `checksum` 判断内容是否变化，未变只更新时间戳；原子写并留 `.old` 备份 | DeepWiki `AdguardTeam/AdGuardHome / 4.2 Filter Lists and Custom Rules`（引用 `internal/filtering/filter.go` L274-306、L485-705、L616-647）、`AGHTechDoc.md` |
| GitHub520 的 AGH 用法：**DNS 封锁清单**（不是允许清单）、更新间隔设 1 小时、勾选"使用过滤器和 Hosts 文件以拦截指定域名" | `521xueweihan/GitHub520` README §2.4 |
| 过滤应答 TTL 默认 10s（`filtering.blocked_response_ttl`） | 多篇 AGH 部署资料一致；属层级 1 文档核查，未在实测环境确认 |
| SmartDNS 测速模式与响应模式 | 官方文档 `pymumu.github.io/smartdns/en/config/check-speed-mode`（`ping` / `tcp:port` / `none`，`first-ping` / `fastest-ip` / `fastest-response`） |

---

## 5. 关键风险清单（按严重度）

1. **"最快 IP" ≠ "这个域名的合法服务器"（最高优先级）**
   泛化到任意域名后，多源 DNS 并集里可能混入 DNS 污染返回的假 IP、CDN 上不承载该域名的 IP、CNAME 链末端的 IP、Anycast 节点。TCP 443 能连上只证明端口开着。
   → **必须加 TLS 校验**：以 `SNI = 目标域名` 对每个候选 IP 做完整 HTTPS 握手并验证证书主机名，等价于 `curl --resolve domain:443:IP https://domain/`；失败直接淘汰。CFST 的 README 也把 `x509: certificate is valid for XXX, not YYY` 列为常见失败原因，可互相印证。
2. **IPv6 / AAAA 绕过**：hosts 规则只影响 A 记录，客户端仍会正常查 AAAA；若 IPv6 优先级更高，优选等于白做。→ 输出 AGH 专用规则时同时抑制 AAAA（`||domain^$dnstype=AAAA,dnsrewrite=NOERROR;;`），或干脆在配置里关闭 IPv6。
3. **HTTPS/SVCB 记录、DoH、ECH**：浏览器可能通过 HTTPS RR 的 `ipv4hint` 或自身 DoH 拿到真实 IP，绕过 hosts。→ 接受这个局限；不要指望 hosts 对现代浏览器 100% 生效。
4. **精确匹配不覆盖子域**：AGH 的 hosts 语法只匹配写出来的那个域名。用户"手动加 `github.com`"不会覆盖 `raw.githubusercontent.com`。→ 要么逐条列全，要么改输出 `$dnsrewrite` 规则用 `||domain^` 覆盖子域。
5. **IP 抖动**：单次测速最优会来回跳，每次变化都触发 AGH 重载过滤引擎。→ 加滞回（新 IP 需比当前快 ≥20% 且连续 2 轮胜出才切换）+ "有变化才写"（GitHub520 已有）。
6. **整轮失败污染全网**：某域名所有候选都校验失败时写空或写错，会让全家设备立刻解析失败。→ **失败不覆盖**：保留上一轮结果、非零退出、告警（直接借鉴 `self-hosted-best-cf-ip-scanner`）。
7. **循环依赖（NAS 场景特有，容易忽略）**
   - 探测容器的 DNS 若指向 AdGuard Home，等于"用待优化的解析结果去找候选 IP"，鸡生蛋且污染会被递归放大 → 容器/进程显式指定外部 DNS（DoH 或 `223.5.5.5` 等），并在 compose 里写死 `dns:`。
   - AGH 拉取订阅 URL 时也会经过自己的解析与过滤规则 → 订阅地址用 **NAS 内网 IP:端口** 或独立内网域名，绝不用自己正在优化的域名。
   - 若 NAS 上有代理/旁路由，测速出口必须直连，否则测的是代理延迟（CFST 与 NestingDNS 都明确警告过）。
8. **探测行为合规**：高频 TCP/HTTP 探测在部分网络环境会被视为扫描。→ 只探测自己配置的域名、限制并发（≤20）、控制频率（建议 30–120 分钟一轮）、保留可追溯日志。
9. **安全边界**：这个服务本质上是"能决定你全网 DNS 指向什么"的端点。→ 仅监听内网、管理接口加认证、订阅端点只读、产物原子写、非 root 运行。不要暴露公网（TinsFox 被刷爆 KV 配额就是前车之鉴）。
10. **许可**：不要复制 GitHub520 代码（CC BY-NC-ND 4.0 含"禁止演绎"）。借鉴算法思路重写；若参考 MIT 项目则保留版权声明；若引入 GPL 组件需注意分发义务。

---

## 6. 推荐架构（最小可用版）

```
domains.yaml（人工维护；可带 per-domain 校验参数）
      │
      ▼
[1] 采集器  DoH(阿里/DNSPod/Google) + 传统DNS(114/阿里/腾讯/CF/Google) → A/AAAA 并集去重
      │      剔除保留地址、已知污染段；可选：手工固定 IP 池
      ▼
[2] 校验器  ★核心★  SNI=域名 的 TLS 握手 + 证书主机名校验（必要时校验 HTTP 状态/路径）
      │      失败即淘汰；全部失败 → 该域名沿用上一轮 IP 并告警
      ▼
[3] 评分器  TCP443 ×3 取中位数；滞回阈值 20% + 连续 2 轮；同 IP 多域名复用测速结果
      ▼
[4] 生成器  原子写三份产物（内容无变化不写）
      ├─ hosts.txt   `# ...` 注释头 + `IP domain`    → 系统 hosts / SwitchHosts / AGH 通用
      ├─ agh.txt     `||domain^$dnsrewrite=NOERROR;A;IP` + AAAA 抑制 → AGH 专用，可覆盖子域
      └─ status.json 每域名当前 IP、延迟、校验结果、上次成功/切换时间
      ▼
[5] 静态 HTTP（仅内网）  Cache-Control: no-cache + ETag/Last-Modified；不要套 CDN 缓存
      ▼
AdGuard Home：过滤器 → DNS 封锁清单 → 自定义列表；更新间隔 1h
```

**输出两种格式是刻意设计**：hosts 语法兼容性最广（AGH 全家族、SwitchHosts、系统 hosts），`$dnsrewrite` 语法能显式指定 A/AAAA、用 `||domain^` 覆盖子域、优先级最高。两个 URL 成本几乎为零，却解决了 hosts 语法最大的短板。

**AdGuard Home 侧必须做的四件事**：
- 加到 **DNS 封锁清单**（不是允许清单）；勾选"使用过滤器和 Hosts 文件以拦截指定域名"
- 把**过滤器更新间隔从默认 24h 改成 1h**（AGH 用 checksum 比对，内容没变不会重载引擎，所以服务端"有变化才写"是对的）
- 生成文件**至少保留 1 条有效规则**（AGH 添加/更新列表时会校验，空列表会被拒绝）；注释头 + 规则即可
- 接受过滤应答 TTL 造成的秒级到分钟级延迟；必要时调 `blocked_response_ttl`

**部署骨架**（单容器即可，不必上数据库）：

```yaml
services:
  hosts-optimizer:
    image: your/hosts-optimizer:latest       # Python 3.13-alpine，非 root
    restart: unless-stopped
    dns: [223.5.5.5, 119.29.29.29]           # ★ 绕开 AdGuard Home，避免循环依赖
    environment:
      TZ: Asia/Shanghai
      SCHEDULE: "*/60 * * * *"               # 或进程内 APScheduler
      PROBE_CONCURRENCY: "20"
    volumes:
      - ./config/domains.yaml:/app/domains.yaml:ro
      - ./output:/app/output                  # 产物与历史落宿主目录，便于回滚
    ports:
      - "8088:8080"                          # 仅内网：http://<NAS内网IP>:8088/hosts.txt
```

订阅 URL 用 `http://192.168.x.x:8088/hosts.txt`。若 NAS 是 fnOS，Docker 命令需要 `sudo` 的既有流程可直接复用；容器时区务必设对（时间戳会影响"有变化才写"的判断与排障）。

**分阶段落地建议**：
1. 只做 3–5 个域名、只出 `hosts.txt`、只做 TCP + TLS 校验，跑一周，观察 IP 是否频繁抖动与校验失败率；
2. 稳定后加 `agh.txt`、滞回、`status.json`、失败告警；
3. 最后才考虑 Web 管理界面（YAML 热加载在早期足够，别一上来就做 UI + 数据库）。

---

## 7. 验证层级与未验证范围

| 结论 | 层级 |
| --- | --- |
| 所有仓库的架构、源码、许可、Star、推送时间 | **1 源码/文档核查**（固定 SHA 见第 4 节） |
| AdGuard Home 对 hosts 语法与过滤列表更新的语义 | **1 文档核查**（官方 wiki + AGHTechDoc + DeepWiki 源码索引） |
| SmartDNS 测速/响应模式 | **1 官方文档核查** |
| 本方案在用户 NAS 上的实际效果、TLS 校验命中率、AGH 重载行为、IP 抖动幅度 | **4 待验证** —— 未部署、未运行、未实测，本文不含任何性能结论 |

未做的事：没有实机部署 AdGuard Home 验证订阅解析结果；没有跑通 TLS 校验样例；没有验证 AGH 对 `$dnsrewrite` 订阅列表的规则数校验细节；没有核对 AGH 是否发送条件请求头（因此服务端返回 ETag/Last-Modified 只是稳妥实践，不是必需项）。

---

## 8. 后续工作（按收益 / 成本排序）

1. **先决策：自研 vs SmartDNS**。若目标只是"家里这几个域名快一点"，把 SmartDNS 挂到 AGH 上游，30 分钟零代码；只有需要订阅 URL / 跨实例复用 / 历史可视化时才自研。
2. 若自研，先写"采集 + TLS 校验 + 生成 hosts.txt"三块的最小原型，用 `curl --resolve` 手工核对 2–3 个域名，确认校验器真能淘汰错误 IP（这是整个项目唯一有区分力的验证）。
3. 落 Docker Compose，重点验证两个循环依赖（容器 DNS、AGH 订阅地址）。
4. 接 AGH 订阅：确认列表被接受（规则数 > 0）、`dig @<AGH_IP> domain` 返回预期 IP、更新间隔 1h 生效。
5. 观察一周后再决定要不要加 UI。

---

## 9. 补充：飞牛 fnOS 部署适配

用户后续明确项目需要「飞牛 OS 原生应用适配 + Docker 部署适配」。该约束会改变核心程序的接口设计（单端口、路径全注入、非 root、不能 ICMP），完整方案与固定源码证据见 `research/2026-11-05-fnos-dual-deployment.md`；可打包的工程骨架已落在 `deploy/`。

最关键的结论：飞牛的「原生应用」与「Docker 应用」是同一个 `.fpk` 包的两种运行模式，由 `config/resource` 中 `docker-project` / `systemd-unit` 切换；因此完整需求实为三条分发轨道（通用 Compose、fnOS Docker 类 FPK、fnOS 纯原生 FPK），其中前两者可共用一份 compose。

**后续修订（同日）**：用户补充「目标网络下 Docker 镜像编译与依赖下载成本过高」，据此把 **fnOS 纯原生 FPK 定为主轨**，两条 Docker 轨冻结为可选。同时把核心实现语言定为 **Go + 仅标准库**：单静态二进制随 `.fpk` 分发，构建机交叉编译、设备安装全程离线；配置由 YAML 改为 `domains.json`（避免引入 YAML 第三方模块）。因此本报告第 6、8 节里「YAML 热加载」「落 Docker Compose」两处建议已被取代，以 `research/2026-11-05-fnos-dual-deployment.md` 第 10 节与 `deploy/README.md` 为准。
