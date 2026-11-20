param(
    [switch]$IncludeCore,
    [switch]$SkipTests,
    [switch]$BuildInstaller
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$pyExe = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $pyExe)) {
    $pyExe = "python"
}

if (-not $SkipTests) {
    Write-Host "==> Running unit tests..."
    & $pyExe -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Unit tests failed with exit code $LASTEXITCODE" }
}

$stageDir = Join-Path $PSScriptRoot "release\StarBridge"
$targetExe = Join-Path $stageDir "StarBridge.exe"
if (Test-Path $targetExe) {
    try {
        $fs = [System.IO.File]::Open($targetExe, 'Open', 'ReadWrite', 'None')
        $fs.Close()
    } catch {
        throw "StarBridge.exe 正在运行中，请先关闭窗口后再重新打包（本次未修改 release 目录）。"
    }
}

$iconArg = @()
$iconFile = Join-Path $PSScriptRoot "assets\starbridge.ico"
if (Test-Path $iconFile) {
    $iconArg = @("--icon", $iconFile)
}

Write-Host "==> Building StarBridge.exe via PyInstaller..."
& $pyExe -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name StarBridge `
    @iconArg `
    --add-data "app\static;app\static" `
    --add-data "assets;assets" `
    --hidden-import webview `
    --hidden-import yaml `
    run_panel.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE" }

# 准备纯发布镜像目录用于打 zip（不包含用户本机 data/）
$zipStage = Join-Path $PSScriptRoot "release\_zip_stage"
if (Test-Path $zipStage) {
    Remove-Item $zipStage -Recurse -Force
}
New-Item -ItemType Directory -Path $zipStage -Force | Out-Null
New-Item -ItemType Directory -Path $stageDir -Force | Out-Null

# 若旧版 WarpRelayPanel\data 存在而新版 data 尚不存在，自动继承用户数据
$oldData = Join-Path $PSScriptRoot "release\WarpRelayPanel\data"
$newData = Join-Path $stageDir "data"
if ((Test-Path $oldData) -and -not (Test-Path $newData)) {
    Copy-Item $oldData -Destination $newData -Recurse -Force
}

Copy-Item "dist\StarBridge.exe" -Destination $targetExe -Force
Copy-Item "dist\StarBridge.exe" -Destination (Join-Path $zipStage "StarBridge.exe") -Force

if ($IncludeCore) {
    $coreSrc = Join-Path $PSScriptRoot "core"
    $coreStageOut = Join-Path $stageDir "core"
    $coreZipOut = Join-Path $zipStage "core"
    if (Test-Path (Join-Path $coreSrc "mihomo.exe")) {
        if (-not (Test-Path (Join-Path $coreSrc "xray.exe"))) {
            Write-Host "==> Downloading missing core/xray.exe..."
            & $pyExe -c "from pathlib import Path; from app import core_updater, win_proxy; core_updater.ensure_xray_exe(Path('core'), proxy_url=win_proxy.get_active_proxy_url())"
            if ($LASTEXITCODE -ne 0) { throw "Failed to download xray.exe" }
        }
        Write-Host "==> Copying core binaries to release..."
        New-Item -ItemType Directory -Path $coreStageOut -Force | Out-Null
        New-Item -ItemType Directory -Path $coreZipOut -Force | Out-Null
        foreach ($fname in @("mihomo.exe", "xray.exe", "geosite.dat", "geoip.dat", "geoip.metadb")) {
            $srcFile = Join-Path $coreSrc $fname
            if (Test-Path $srcFile) {
                Copy-Item $srcFile -Destination (Join-Path $coreStageOut $fname) -Force
                Copy-Item $srcFile -Destination (Join-Path $coreZipOut $fname) -Force
            }
        }
    } else {
        Write-Host "==> Downloading mihomo.exe, xray.exe and GeoIP/GeoSite files..."
        & $pyExe -c "from pathlib import Path; from app import core_updater, win_proxy; core_updater.download_core_assets(Path(r'$coreStageOut'), proxy_url=win_proxy.get_active_proxy_url(), include_xray=True)"
        if ($LASTEXITCODE -ne 0) { throw "Failed to download core assets" }
        Copy-Item $coreStageOut -Destination $coreZipOut -Recurse -Force
    }
}

$zipPath = Join-Path $PSScriptRoot "release\StarBridge-win64.zip"
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}
Compress-Archive -Path "$zipStage\*" -DestinationPath $zipPath -Force
Remove-Item $zipStage -Recurse -Force
Write-Host "==> Done: $zipPath"

if ($BuildInstaller) {
    $setupExe = Join-Path $PSScriptRoot "release\StarBridge-Setup.exe"
    Write-Host "==> Building StarBridge-Setup.exe installer..."
    & $pyExe -m PyInstaller --noconfirm --clean --onefile --windowed `
        --name StarBridge-Setup `
        @iconArg `
        --add-data "release\StarBridge-win64.zip;." `
        --add-data "assets;assets" `
        installer.py
    if ($LASTEXITCODE -ne 0) { throw "Installer PyInstaller failed with exit code $LASTEXITCODE" }
    Copy-Item "dist\StarBridge-Setup.exe" -Destination $setupExe -Force
    Write-Host "==> Done Installer: $setupExe"
}
