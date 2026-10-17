# Removes the Blacknet service, firewall rules and installation.
# Run elevated. Keeps $InstallDir\data (your database) unless -Purge is given.

param(
    [string]$InstallDir = "$env:ProgramData\Blacknet",
    [switch]$Purge
)

$ErrorActionPreference = 'Stop'
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
}

$svc = Get-Service -Name 'Blacknet' -ErrorAction SilentlyContinue
if ($svc) {
    Stop-Service Blacknet -Force -ErrorAction SilentlyContinue
    sc.exe delete Blacknet | Out-Null
    Write-Host "Service removed."
}
foreach ($name in 'Blacknet DNS UDP', 'Blacknet DNS TCP', 'Blacknet Dashboard TCP') {
    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
}
Write-Host "Firewall rules removed."

if ($Purge) {
    Remove-Item $InstallDir -Recurse -Force
    Write-Host "Removed $InstallDir including data."
} else {
    Write-Host "Kept $InstallDir (delete manually, or re-run with -Purge)."
}
