param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$EthosArgs
)
$ErrorActionPreference = "Stop"
if (-not (Get-Command lockit -ErrorAction SilentlyContinue)) {
    throw "Install Lockit from its official release first. See docs/lockit-integration.md."
}
if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot "../.lockit"))) {
    throw "Initialize and authorize the Lockit project yourself before using this launcher."
}
Push-Location (Join-Path $PSScriptRoot "..")
try {
    & lockit run -- cargo run -- @EthosArgs
    exit $LASTEXITCODE
}
finally { Pop-Location }
