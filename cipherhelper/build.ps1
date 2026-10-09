# Builds cipher-helper for the Xiaomi Mi Router AC2100 (MediaTek MT7621:
# little-endian MIPS, soft float).  Requires the Go toolchain in tools\go.
$ErrorActionPreference = "Stop"

$Go     = "C:\Users\plaui\Documents\Codex\tools\go\bin\go.exe"
$Root   = Split-Path -Parent $MyInvocation.MyCommand.Path
$Output = Join-Path $Root "dist\cipher-helper-mipsle"

if (-not (Test-Path $Go)) { throw "Go toolchain not found at $Go" }

$env:GOPATH      = "C:\Users\plaui\Documents\Codex\tools\gopath"
$env:GOFLAGS     = "-mod=mod"
$env:CGO_ENABLED = "0"
$env:GOOS        = "linux"
$env:GOARCH      = "mipsle"
$env:GOMIPS      = "softfloat"

New-Item -ItemType Directory -Force -Path (Split-Path $Output) | Out-Null
Push-Location $Root
try {
    & $Go build -trimpath -ldflags="-s -w" -o $Output .
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
} finally {
    Pop-Location
}

$item = Get-Item $Output
Write-Host ("built {0} ({1:N0} bytes)" -f $item.FullName, $item.Length)
Write-Host "deploy:  scp -O $Output root@192.168.1.1:/root/portal/cipher-helper"
Write-Host "verify:  ssh root@192.168.1.1 'chmod 700 /root/portal/cipher-helper; /root/portal/cipher-helper list'"
