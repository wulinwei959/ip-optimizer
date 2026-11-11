#!/usr/bin/env bash
# 在构建机上交叉编译 Go 静态二进制并打包 fnOS 原生 FPK。
#
# 设计目标：除一次性安装 Go SDK 外，全程不需要网络。
#   - 核心只用 Go 标准库：GOPROXY=off 会在误引入第三方依赖时直接失败，而不是偷偷联网
#   - 交叉编译在 Windows / macOS 上即可产出 Linux ELF，不需要 Linux 机器或 Docker daemon
#   - 二进制随 .fpk 分发，fnOS 设备安装时完全离线，不拉镜像、不装运行时、不 pip install
#
# 用法：
#   ./deploy/scripts/build-native-fpk.sh x86        # amd64 二进制 + platform=x86 的 fpk
#   ./deploy/scripts/build-native-fpk.sh arm        # arm64 二进制 + platform=arm 的 fpk
#   SKIP_PACK=1 ./deploy/scripts/build-native-fpk.sh x86   # 只编译，不调 fnpack（用于先验证产物）
#   CORE_DIR=/path/to/core ./deploy/scripts/build-native-fpk.sh x86
#   FNPACK=/path/to/fnpack ./deploy/scripts/build-native-fpk.sh x86
set -euo pipefail

ARCH_ARG="${1:-}"
case "$ARCH_ARG" in
  x86|amd64) GOARCH=amd64; FPK_PLATFORM=x86; FPK_SUFFIX=x86 ;;
  arm|arm64) GOARCH=arm64; FPK_PLATFORM=arm; FPK_SUFFIX=arm ;;
  *) echo "用法: $0 <x86|arm>   （等价于 amd64|arm64）" >&2; exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CORE_DIR="${CORE_DIR:-$ROOT/core}"
SRC_FPK="$ROOT/deploy/fnos-native-fpk"
DIST="$ROOT/deploy/dist"
GO_PACKAGE="${GO_PACKAGE:-./cmd/hosts-optimizer}"
FNPACK="${FNPACK:-fnpack}"

command -v go >/dev/null 2>&1 || { echo "未找到 go：请先在本机安装 Go SDK（唯一的一次性下载）。" >&2; exit 1; }
[ -f "$CORE_DIR/go.mod" ] || { echo "未找到核心工程 $CORE_DIR/go.mod；用 CORE_DIR 指定，或先实现核心。" >&2; exit 1; }
[ -d "$SRC_FPK" ] || { echo "未找到 FPK 源工程 $SRC_FPK" >&2; exit 1; }

if [ "${SKIP_PACK:-0}" != "1" ]; then
  command -v "$FNPACK" >/dev/null 2>&1 || { echo "未找到 fnpack：从 https://developer.fnnas.com/docs/cli/fnpack/ 下载，或用 FNPACK=/path 指定；也可 SKIP_PACK=1 只编译。" >&2; exit 1; }
fi

VERSION="$(sed -n 's/^version=//p' "$SRC_FPK/manifest" | head -1 | tr -d '[:space:]')"
[ -n "$VERSION" ] || { echo "manifest 缺少 version" >&2; exit 1; }

STG="$(mktemp -d)"
# Git Bash 的 mktemp 可能返回 C:\... 风格路径，统一转成 MSYS 路径，
# 否则后续路径拼接与清理会因盘符/反斜杠失败。
if command -v cygpath >/dev/null 2>&1; then
  STG="$(cygpath -u "$STG")"
fi
cleanup() {
  if [ "${SKIP_PACK:-0}" = "1" ]; then
    echo "保留 staging 目录（SKIP_PACK=1）：$STG"
  else
    [ -n "${STG:-}" ] && [ -d "$STG" ] && rm -rf -- "$STG"
  fi
}
trap cleanup EXIT

cp -a "$SRC_FPK/." "$STG/"
mkdir -p "$STG/app/bin" "$DIST"
printf '%s\n' '本目录由 build-native-fpk.sh 注入静态二进制 hosts-optimizer。' > "$STG/app/bin/README.md"

echo "[1/5] 交叉编译 GOOS=linux GOARCH=$GOARCH（GOPROXY=off，强制零依赖）"
(
  cd "$CORE_DIR"
  CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH" GOPROXY=off GOSUMDB=off \
    go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$STG/app/bin/hosts-optimizer" "$GO_PACKAGE"
)
chmod +x "$STG/app/bin/hosts-optimizer"

echo "[2/5] 放入配置模板"
cp "$ROOT/deploy/config-schema/domains.example.json" "$STG/app/domains.example.json"

echo "[3/5] CA 根证书（可选）"
if [ -f "$ROOT/deploy/ca-bundle.crt" ]; then
  cp "$ROOT/deploy/ca-bundle.crt" "$STG/app/ca-bundle.crt"
  echo "      已随包携带 ca-bundle.crt"
else
  echo "      未找到 deploy/ca-bundle.crt：核心将回落到 fnOS 系统证书池（Debian 系一般可用）"
fi

echo "[4/5] 写入 manifest.platform=$FPK_PLATFORM"
sed -i "s/^platform=.*/platform=$FPK_PLATFORM/" "$STG/manifest"
chmod +x "$STG"/cmd/* 2>/dev/null || true

if [ "${SKIP_PACK:-0}" = "1" ]; then
  echo "[5/5] 跳过打包。二进制：$STG/app/bin/hosts-optimizer"
  ls -lh "$STG/app/bin/hosts-optimizer"
  exit 0
fi

echo "[5/5] fnpack build"
( cd "$STG" && "$FNPACK" build --directory "$STG" )
FPK="$(find "$STG" -maxdepth 3 -name '*.fpk' -type f -print -quit)"
[ -n "$FPK" ] || { echo "未找到 fnpack 产出的 .fpk，请检查 fnpack 输出位置。" >&2; exit 1; }
OUT="$DIST/hosts-optimizer-native-${VERSION}-${FPK_SUFFIX}.fpk"
mv "$FPK" "$OUT"
echo "完成：$OUT"
echo "安装：应用中心 → 手动安装 → 上传该 .fpk（订阅地址 http://<NAS内网IP>:18088/hosts.txt）"
