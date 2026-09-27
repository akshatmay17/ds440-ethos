# TaintBox Windows Build & Packaging Script
# Compiles tbox.exe CLI and generates WiX MSI & NSIS Setup.exe installers via Tauri v2

param(
    [switch]$SkipCli = $false,
    [switch]$SkipDesktop = $false
)

$ErrorActionPreference = "Stop"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  TaintBox Windows Build & Installer Generator" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Verify Rust Toolchain
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Error "Cargo was not found in PATH. Please install Rust from https://rustup.rs"
    exit 1
}

$DistDir = Join-Path $PSScriptRoot "..\dist\windows"
New-Item -ItemType Directory -Force -Path $DistDir | Out-Null

# 2. Build CLI & Daemon Binaries
if (-not $SkipCli) {
    Write-Host "`n[1/3] Building Standalone CLI & Daemon (tbox.exe)..." -ForegroundColor Yellow
    Push-Location (Join-Path $PSScriptRoot "..")
    try {
        cargo build --release --bin tbox --bin taintbox
        Copy-Item "target\release\tbox.exe" -Destination "$DistDir\tbox.exe" -Force
        Copy-Item "target\release\taintbox.exe" -Destination "$DistDir\taintbox.exe" -Force
        Write-Host "  -> CLI compiled to $DistDir\tbox.exe" -ForegroundColor Green
    } finally {
        Pop-Location
    }
}

# 3. Build Desktop Application & Installers (MSI + NSIS)
if (-not $SkipDesktop) {
    Write-Host "`n[2/3] Checking Tauri CLI..." -ForegroundColor Yellow
    if (-not (Get-Command "cargo-tauri" -ErrorAction SilentlyContinue) -and -not (Get-Command "tauri" -ErrorAction SilentlyContinue)) {
        Write-Host "Installing tauri-cli v2..." -ForegroundColor Yellow
        cargo install tauri-cli --version "^2.0.0" --locked
    }

    Write-Host "`n[2/3] Building Desktop App & Installers (WiX MSI + NSIS Setup)..." -ForegroundColor Yellow
    Push-Location (Join-Path $PSScriptRoot "..\apps\desktop")
    try {
        cargo tauri build
        
        $BundleBase = "src-tauri\target\release\bundle"
        if (Test-Path $BundleBase) {
            # Copy MSI
            Get-ChildItem -Path "$BundleBase\msi\*.msi" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item $_.FullName -Destination "$DistDir\$($_.Name)" -Force
                Write-Host "  -> Generated MSI: $($_.Name)" -ForegroundColor Green
            }
            # Copy NSIS
            Get-ChildItem -Path "$BundleBase\nsis\*setup*.exe" -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                Copy-Item $_.FullName -Destination "$DistDir\$($_.Name)" -Force
                Write-Host "  -> Generated NSIS Setup: $($_.Name)" -ForegroundColor Green
            }
        }
    } finally {
        Pop-Location
    }
}

# 4. Package CLI Zip & Generate Checksums
Write-Host "`n[3/3] Generating Checksums & Portable Zip..." -ForegroundColor Yellow
if ((Test-Path "$DistDir\tbox.exe") -and (Test-Path "$DistDir\taintbox.exe")) {
    Compress-Archive -Path "$DistDir\tbox.exe", "$DistDir\taintbox.exe" -DestinationPath "$DistDir\tbox-windows-x64-cli.zip" -Force
}

$SumFile = "$DistDir\SHA256SUMS.txt"
if (Test-Path $SumFile) { Remove-Item $SumFile -Force }

Get-ChildItem $DistDir -File | Where-Object { $_.Name -ne "SHA256SUMS.txt" } | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower()
    "$hash  $($_.Name)" | Out-File -FilePath $SumFile -Append -Encoding ascii
}

Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host "  Build Complete! Windows artifacts staged in:" -ForegroundColor Green
Write-Host "  $DistDir" -ForegroundColor White
Get-ChildItem $DistDir | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "============================================================" -ForegroundColor Cyan
