# 静态二进制放置位置（占位）

构建脚本 `deploy/scripts/build-native-fpk.sh` 会把交叉编译产物放到本目录，对应安装后的 `$TRIM_APPDEST/bin/hosts-optimizer`：

```text
app/bin/hosts-optimizer   # CGO_ENABLED=0 的 Linux 静态 ELF，按 x86 / arm 分别构建
app/ca-bundle.crt         # 可选：Mozilla CA 根证书，供 TLS 校验回落使用
```

**要求**

- 单个可执行文件，不依赖 glibc 之外的动态库、不依赖 Python/Node/Java 运行时
- 不调用 ICMP（`run-as=package` 无 `cap_net_raw`），只做 TCP 443 + TLS/SNI 校验
- 监听 `$HO_PORT` 单端口，提供 `/`、`/hosts.txt`、`/agh.txt`、`/status.json`
- 配置读 `$HO_CONFIG/domains.json`，产物写 `$HO_OUTPUT`，状态写 `$HO_STATE`
- 进程内定时（`schedule_minutes`），不依赖宿主 crontab
- 原子写产物；整轮校验全灭时保留上一轮结果，绝不写空文件

本目录当前只有说明文件，尚无可运行二进制。
