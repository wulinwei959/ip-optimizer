# Pull Request 模板

## 变更类型
- [ ] 文档
- [ ] 功能
- [ ] 修复
- [ ] 重构
- [ ] 测试
- [ ] 构建
- [ ] 配置
- [ ] 仓库配置

## 变更说明
<!-- 简述做了什么、为什么、影响范围 -->

## 关联 Issue / PR
<!-- 如：修复 #123，关联 #456 -->

## 本地验收清单
- [ ] `GOPROXY=off go vet ./...` 无警告
- [ ] `GOPROXY=off go test ./... -v` 全部通过
- [ ] `SKIP_PACK=1 ./deploy/scripts/build-native-fpk.sh x86` 编译通过（或 .ps1）
- [ ] `probe_dns` 字段校验：必须为字面 IP
- [ ] 原子写：所有产物使用 `os.Rename(tmp, target)`
- [ ] 失败不丢规则：整轮全失败时 `hosts.txt` 503，`status.json` 200 ready=false

## 代码注释
- [ ] 所有新增/修改代码注释为简体中文
- [ ] 包注释遵循 Go 规范（中文内容）

## 合并策略
- [ ] 确认使用 **Squash and merge**，一个 PR 对应一个最终 commit

---

> 详细规范见 [CONTRIBUTING.md](../CONTRIBUTING.md)