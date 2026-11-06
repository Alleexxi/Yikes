param([string]$Emulator)
$ErrorActionPreference = 'Stop'
$taskRoot = $PSScriptRoot
$taskPython = Join-Path $taskRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $taskPython)) {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3 -m venv (Join-Path $taskRoot '.venv')
    } else {
        & python -m venv (Join-Path $taskRoot '.venv')
    }
    if ($LASTEXITCODE -ne 0) { throw 'Python environment creation failed' }
}
& $taskPython -m pip install -r (Join-Path $taskRoot 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed' }
if ($Emulator) {
    & (Join-Path $taskRoot 'yikes.cmd') configure --emulator $Emulator
} else {
    & (Join-Path $taskRoot 'yikes.cmd') update
}
if ($LASTEXITCODE -ne 0) { throw 'Emulator configuration failed' }
Write-Host "Ready: $(Join-Path $taskRoot 'yikes.cmd')"
