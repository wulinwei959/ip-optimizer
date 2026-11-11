#!/usr/bin/env pwsh
# Cross-compile the Go static binary and package the fnOS native FPK (PowerShell port, no bash needed).
#
# Goal: apart from a one-time Go SDK install, the whole flow needs no network.
#   - Core uses only Go stdlib: GOPROXY=off fails loudly if a 3rd-party dep sneaks in.
#   - Cross-compile on Windows produces a Linux ELF (no Linux host, no Docker daemon).
#   - Binary ships inside the .fpk; fnOS install is fully offline.
#
# Usage:
#   pwsh deploy/scripts/build-native-fpk.ps1 x86        # amd64 binary + platform=x86 fpk
#   pwsh deploy/scripts/build-native-fpk.ps1 arm        # arm64 binary + platform=arm fpk
#   $env:SKIP_PACK=1; pwsh deploy/scripts/build-native-fpk.ps1 x86   # compile only, skip fnpack
#   $env:CORE_DIR=/path/to/core; pwsh deploy/scripts/build-native-fpk.ps1 x86
#   $env:FNPACK=/path/to/fnpack; pwsh deploy/scripts/build-native-fpk.ps1 x86

$ErrorActionPreference = 'Stop'

$ARCH_ARG = $args[0]
if ($ARCH_ARG -in 'x86','amd64') {
  $GOARCH='amd64'; $FPK_PLATFORM='x86'; $FPK_SUFFIX='x86'
} elseif ($ARCH_ARG -in 'arm','arm64') {
  $GOARCH='arm64'; $FPK_PLATFORM='arm'; $FPK_SUFFIX='arm'
} else {
  Write-Error "Usage: $($MyInvocation.MyCommand.Name) <x86|arm>   (equiv amd64|arm64)"
  exit 2
}

$ROOT   = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$CORE_DIR = if ($env:CORE_DIR) { $env:CORE_DIR } else { Join-Path $ROOT 'core' }
$SRC_FPK  = Join-Path $ROOT 'deploy\fnos-native-fpk'
$DIST     = Join-Path $ROOT 'deploy\dist'
$GO_PACKAGE = if ($env:GO_PACKAGE) { $env:GO_PACKAGE } else { '.\cmd\hosts-optimizer' }
$FNPACK   = if ($env:FNPACK) { $env:FNPACK } else { 'fnpack' }

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
  Write-Error 'go not found: install the Go SDK first (the only one-time download).'; exit 1
}
if (-not (Test-Path (Join-Path $CORE_DIR 'go.mod'))) {
  Write-Error "core project missing: $CORE_DIR\go.mod (set CORE_DIR or implement core)."; exit 1
}
if (-not (Test-Path $SRC_FPK)) {
  Write-Error "FPK source tree missing: $SRC_FPK"; exit 1
}
if (($env:SKIP_PACK -ne '1') -and -not (Get-Command $FNPACK -ErrorAction SilentlyContinue)) {
  Write-Error "fnpack not found: download from https://developer.fnnas.com/docs/cli/fnpack/ or set FNPACK=/path (or set SKIP_PACK=1 to compile only)."; exit 1
}

$verLine = Select-String -Path (Join-Path $SRC_FPK 'manifest') -Pattern '^version=' | Select-Object -First 1
$VERSION = if ($verLine) { ($verLine.Line -split '=', 2)[1].Trim() } else { '' }
if (-not $VERSION) { Write-Error 'manifest missing version'; exit 1 }

$STG = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("ho-stg-" + [guid]::NewGuid().ToString('N'))) | Select-Object -ExpandProperty FullName

function cleanup {
  if ($env:SKIP_PACK -eq '1') {
    Write-Host "Kept staging dir (SKIP_PACK=1): $STG"
  } else {
    if ($STG -and (Test-Path $STG)) { Remove-Item -Recurse -Force $STG }
  }
}
trap { cleanup; throw $_ }

Copy-Item -Recurse -Force "$SRC_FPK\*" "$STG\"
New-Item -ItemType Directory -Force -Path "$STG\app\bin", $DIST | Out-Null
Set-Content -Path "$STG\app\bin\README.md" -Value 'This dir receives the static binary hosts-optimizer injected by build-native-fpk.ps1.'

Write-Host "[1/5] cross-compile GOOS=linux GOARCH=$GOARCH (GOPROXY=off, force zero deps)"
$oldGOOS=$env:GOOS; $oldGOARCH=$env:GOARCH; $oldCGO=$env:CGO_ENABLED; $oldPROXY=$env:GOPROXY; $oldSUM=$env:GOSUMDB
$env:GOOS='linux'; $env:GOARCH=$GOARCH; $env:CGO_ENABLED='0'; $env:GOPROXY='off'; $env:GOSUMDB='off'
try {
  Push-Location $CORE_DIR
  & go build -trimpath -ldflags="-s -w -X main.version=$VERSION" -o (Join-Path $STG 'app\bin\hosts-optimizer') $GO_PACKAGE
  if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
} finally { Pop-Location }
$env:GOOS=$oldGOOS; $env:GOARCH=$oldGOARCH; $env:CGO_ENABLED=$oldCGO; $env:GOPROXY=$oldPROXY; $env:GOSUMDB=$oldSUM

Write-Host '[2/5] copy config template'
Copy-Item (Join-Path $ROOT 'deploy\config-schema\domains.example.json') (Join-Path $STG 'app\domains.example.json')

Write-Host '[3/5] CA bundle (optional)'
$caBundle = Join-Path $ROOT 'deploy\ca-bundle.crt'
if (Test-Path $caBundle) {
  Copy-Item $caBundle (Join-Path $STG 'app\ca-bundle.crt')
  Write-Host '      bundled ca-bundle.crt'
} else {
  Write-Host '      no deploy/ca-bundle.crt: core falls back to fnOS system cert pool (Debian-based usually OK)'
}

Write-Host "[4/5] set manifest.platform=$FPK_PLATFORM"
$manifestPath = Join-Path $STG 'manifest'
$lines = Get-Content -Encoding utf8 $manifestPath
$lines = $lines | ForEach-Object { if ($_ -match '^platform=') { "platform=$FPK_PLATFORM" } else { $_ } }
Set-Content -Path $manifestPath -Encoding utf8 -Value $lines

if ($env:SKIP_PACK -eq '1') {
  Write-Host "[5/5] skip packaging. binary: $(Join-Path $STG 'app\bin\hosts-optimizer')"
  Get-Item (Join-Path $STG 'app\bin\hosts-optimizer') | Select-Object FullName, Length
  exit 0
}

Write-Host '[5/5] fnpack build'
Push-Location $STG
& $FNPACK build --directory $STG
if ($LASTEXITCODE -ne 0) { throw 'fnpack build failed' }
Pop-Location

$FPK = Get-ChildItem -Path $STG -Recurse -Filter '*.fpk' -File | Select-Object -First 1
if (-not $FPK) { Write-Error 'no .fpk produced by fnpack; check fnpack output location.'; exit 1 }
$OUT = Join-Path $DIST "hosts-optimizer-native-$VERSION-$FPK_SUFFIX.fpk"
Move-Item -Force $FPK.FullName $OUT
Write-Host "Done: $OUT"
Write-Host "Install: App Center -> Manual Install -> upload the .fpk (subscribe at http://<NAS_LAN_IP>:18088/hosts.txt)"
