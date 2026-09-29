# ==============================================================================
# ETHOS BENCHMARK EVALUATION RUNNER — WINDOWS POWERSHELL
# Group 2 Nittany Street — DS 440 Capstone
# Compatible with Windows PowerShell 5.1 and PowerShell Core 7+
# ==============================================================================

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet("injecagent", "hackaprompt", "agenthijack", "synthetic", "all")]
    [string]$Dataset = "all",

    [Parameter()]
    [string]$Provider = "lmstudio",

    [Parameter()]
    [string]$Model = "deepseek-r1",

    [Parameter()]
    [ValidateSet("train", "eval", "val", "test", "all")]
    [string]$Split = "all",

    [Parameter()]
    [string]$Output = "",

    [Parameter()]
    [switch]$Synthetic,

    [Parameter()]
    [switch]$Headless
)

function Write-Banner {
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "  ETHOS BENCHMARK & ADVERSARIAL EVALUATION HARNESS (WINDOWS)" -ForegroundColor Cyan
    Write-Host "  Group 2 Nittany Street — Cyber Dark Runtime" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Test-LMStudio {
    try {
        $resp = Invoke-RestMethod -Uri "http://localhost:1234/v1/models" -TimeoutSec 2 -ErrorAction Stop
        Write-Host "[✔] LM Studio server detected online at http://localhost:1234" -ForegroundColor Green
        return $true
    } catch {
        Write-Host "[!] Notice: LM Studio is offline at http://localhost:1234." -ForegroundColor Yellow
        Write-Host "    Evaluation will run using the deterministic security harness driver." -ForegroundColor Gray
        return $false
    }
}

# Interactive selection if run in terminal without explicit switches
if (-not $Headless -and $Dataset -eq "all" -and -not $Synthetic.IsPresent -and $Split -eq "all" -and [Environment]::UserInteractive) {
    Write-Banner
    $null = Test-LMStudio
    Write-Host ""
    Write-Host "Select Evaluation Suite to Execute:" -ForegroundColor White
    Write-Host "  [1] All Datasets (InjecAgent + HackAPrompt + AgentHijack)" -ForegroundColor Magenta
    Write-Host "  [2] Harsh's Suite:    InjecAgent (Indirect Tool Injections)" -ForegroundColor Cyan
    Write-Host "  [3] Aryamaan's Suite: HackAPrompt (Direct Jailbreaks & DAN)" -ForegroundColor Cyan
    Write-Host "  [4] Saathvik's Suite: AgentHijack (Multi-Turn Goal Drift)" -ForegroundColor Cyan
    Write-Host "  [5] Synthetic Adversarial Suite (Base64, Homoglyphs, Fusions)" -ForegroundColor Green
    Write-Host "  [6] Run 70% Training / Calibration Split" -ForegroundColor Yellow
    Write-Host "  [7] Run 20% Validation / Dev Split" -ForegroundColor Yellow
    Write-Host "  [8] Run 10% Zero-Day Blind Test Holdout" -ForegroundColor Red
    Write-Host "  [9] Launch Cyber Dark Interactive TUI" -ForegroundColor White
    Write-Host "  [q] Quit" -ForegroundColor DarkGray
    Write-Host ""

    $choice = Read-Host "Select option [1-9]"

    switch ($choice) {
        "1" { $Dataset = "all" }
        "2" { $Dataset = "injecagent" }
        "3" { $Dataset = "hackaprompt" }
        "4" { $Dataset = "agenthijack" }
        "5" { $Dataset = "synthetic" }
        "6" { $Dataset = "all"; $Split = "train" }
        "7" { $Dataset = "all"; $Split = "eval" }
        "8" { $Dataset = "all"; $Split = "test" }
        "9" {
            Write-Host "Launching Cyber Dark Ratatui TUI..." -ForegroundColor Cyan
            & cargo run --bin ethos -- tui
            exit 0
        }
        "q" { exit 0 }
        default { $Dataset = "all" }
    }
}

$cargoArgs = @("run", "--bin", "ethos", "--", "eval", "--dataset", $Dataset, "--provider", $Provider, "--model", $Model, "--split", $Split)

if ($Synthetic.IsPresent) {
    $cargoArgs += "--synthetic"
}

if ($Output -ne "") {
    $cargoArgs += @("--output", $Output)
}

Write-Host "Executing Ethos Evaluation Harness via Cargo..." -ForegroundColor Cyan
& cargo @cargoArgs
