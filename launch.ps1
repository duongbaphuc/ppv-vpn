$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonW = Join-Path $Root ".venv\Scripts\pythonw.exe"
$Python = Join-Path $Root ".venv\Scripts\python.exe"

if (Test-Path $PythonW) {
    Start-Process -FilePath $PythonW -ArgumentList "-m ppv" -WorkingDirectory $Root
} elseif (Test-Path $Python) {
    & $Python -m ppv
} else {
    Write-Error "Chưa tìm thấy .venv. Hãy cài môi trường Python trước."
}
