# 贡献指南

## Git 提交规范

### 提交信息格式
```
<类别>：<中文说明> （第 N 号合并请求）
```

**类别**（必须中文）：
- `文档` —— 仅文档变更
- `功能` —— 新增特性
- `修复` —— Bug 修复
- `重构` —— 代码重构，无行为变更
- `测试` —— 测试用例增删改
- `构建` —— 构建脚本、CI、依赖变更
- `配置` —— 配置文件、环境变量、schema 变更
- `仓库配置` —— .gitignore、.gitattributes、LICENSE 等仓库级配置

**示例**：
```
文档：补充仓库 README 并修正部署文档中的过时状态（第 1 号合并请求）
修复：probe_dns 域名校验逻辑，禁止非字面 IP（第 5 号合并请求）
功能：新增 /api/domains 在线编辑 domains.json（第 8 号合并请求）
```

### 代码注释
- **全部简体中文**，包含包注释、函数注释、行内注释
- 导出标识符的包注释遵循 Go 规范（`// Package xxx ...`），但内容用中文
- 变量名、字段名保持 `snake_case`，JSON tag 对应字段名

### 合并策略
- **Squash and merge**：一个 PR 合并为一个 commit 进入 `main`
- PR 分支上可保留细粒度 commit，合并时压缩
- `main` 分支历史保持线性、整洁

---

## 开发环境要求
- Go 1.21+（推荐 1.23.4）
- `GOPROXY=off GOSUMDB=off` **完全离线构建**
- `CGO_ENABLED=0` 产出纯静态 Linux ELF
- 仅使用 Go 标准库，**零第三方依赖**（`go.mod` 仅含 `module hosts-optimizer` + `go 1.21`）

---

## 本地验收清单（提交前必须通过）
```bash
cd core
GOPROXY=off go vet ./...
GOPROXY=off go test ./... -v
SKIP_PACK=1 ./../deploy/scripts/build-native-fpk.sh x86   # 或 .ps1 验证跨平台编译
```

关键检查点：
- [ ] `go vet` 无警告
- [ ] 所有测试通过
- [ ] `CGO_ENABLED=0 GOOS=linux GOARCH=amd64|arm64` 交叉编译成功
- [ ] `probe_dns` 字段校验：必须为字面 IP（`net.ParseIP` 非 nil）
- [ ] 原子写：所有产物（hosts.txt/agh.txt/status.json/state.json）使用 `os.Rename(tmp, target)`
- [ ] 失败不丢规则：整轮探测全失败时 `hosts.txt` 返回 503，`status.json` 返回 200 且 `ready=false`

---

## FPK 打包验证（可选，需 fnpack 1.2.3）
```bash
./deploy/scripts/build-native-fpk.sh x86   # 产出 deploy/dist/hosts-optimizer-native-<ver>-x86.fpk
./deploy/scripts/build-native-fpk.sh arm   # 产出 deploy/dist/hosts-optimizer-native-<ver>-arm.fpk
```
检查产物结构：
```
.fpk (解压后)
├── manifest              # platform=x86|arm, service_port=18088, desktop_uidir=ui
├── config/privilege      # run-as=package
├── config/resource       # {"systemd-unit": {}}
├── cmd/main              # source common + service-setup
├── cmd/service-setup     # SERVICE_COMMAND 含 HO_* 环境变量
├── cmd/install_callback  # chmod 755 + 首次生成 domains.json
├── app/bin/hosts-optimizer  # 静态 ELF
├── app/ca-bundle.crt     # 可选
├── app/domains.example.json
├── app/ui/config         # iframe -> http://:18088/
└── wizard/install        # 安装向导 JSON
```

---

## 关键设计约束（不可违背）
| 约束 | 说明 |
|------|------|
| **仅标准库** | 禁止引入任何第三方包 |
| **离线构建** | `GOPROXY=off`，CI/构建机无网络依赖 |
| **静态二进制** | `CGO_ENABLED=0`，无 glibc 以外动态依赖 |
| **非 root 运行** | `run-as=package`，仅 TCP/TLS 端口，**禁 ICMP** |
| **UDP 上游必须是 IP** | `probe_dns` 的 UDP 上游仅接受字面 IP；DoT/DoH 允许主机名并由 TLS 校验 |
| **CA 降级不报错** | 优先 `x509.SystemCertPool()`，缺 `ca-bundle.crt` 只警告继续 |
| **原子写** | 临时文件 + `sync` + `Rename`，防止读到半截文件 |
| **配置热加载** | 每轮重读 `domains.json`，修改即生效无需重启 |
| **单端口 HTTP** | 所有界面（UI、API、产物下载）共用 `HO_PORT`（FPK 固定 18088） |
| **推荐 agh.txt** | AGH 主推 `$dnsrewrite` 格式，自动 AAAA NODATA，覆盖子域名 |

---

## 文档维护
- `README.md`：项目总览、快速开始、三通道对比
- `docs/technical.md`：架构、数据模型、API、并发与扩展
- `docs/progress.md`：版本历史、功能矩阵、验证记录与路线图
- `deploy/README.md`：构建部署细节、环境变量、schema
- `deploy/config-schema/README.md`：`domains.json` 完整字段说明
- `research/`：调研记录，**不可作为现状参考**，以核心代码与部署文档为准
