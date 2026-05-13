L$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot
if (-not (Test-Path ".\data\admin-auth.json")) {
  Write-Host "Premiere installation: configure le compte admin." -ForegroundColor Cyan
  node .\tools\setup-admin.cjs
}
Write-Host "Demarrage Lexa server sur http://127.0.0.1:4173" -ForegroundColor Green
node .\server.js
