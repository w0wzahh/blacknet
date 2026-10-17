# Blacknet Windows install script.
# Run in an elevated PowerShell:  powershell -ExecutionPolicy Bypass -File install.ps1
#
# What it does:
#   1. Copies blacknet.exe + config.yaml + web assets to $env:ProgramData\Blacknet
#   2. Adds narrowly-scoped inbound firewall rules (UDP/TCP 53, TCP dashboard port)
#   3. Registers and starts a Windows service via sc.exe
#
# Re-run uninstall.ps1 to remove everything.

param(
    [string]$SourceDir = $PSScriptRoot,
    [string]$InstallDir = "$env:ProgramData\Blacknet",
    [int]$WebPort = 8080
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this script as Administrator."
}

Write-Host "Installing Blacknet to $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path "$InstallDir\web" | Out-Null

Copy-Item "$SourceDir\blacknet.exe" "$InstallDir\blacknet.exe" -Force
if (-not (Test-Path "$InstallDir\config.yaml")) {
    Copy-Item "$SourceDir\config.yaml" "$InstallDir\config.yaml"
    Write-Host "Wrote default config — edit $InstallDir\config.yaml as needed."
}
Copy-Item "$SourceDir\web\dist" "$InstallDir\web\dist" -Recurse -Force

# --- Firewall: DNS (53 UDP+TCP) and the dashboard port, LAN profile only ---
foreach ($rule in @(
    @{ Name = 'Blacknet DNS UDP'; Port = 53; Proto = 'UDP' },
    @{ Name = 'Blacknet DNS TCP'; Port = 53; Proto = 'TCP' },
    @{ Name = "Blacknet Dashboard TCP"; Port = $WebPort; Proto = 'TCP' }
)) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Action Allow `
            -Protocol $rule.Proto -LocalPort $rule.Port -Profile Private | Out-Null
        Write-Host "Firewall rule added: $($rule.Name)"
    }
}

# --- Service ---
$exe = "`"$InstallDir\blacknet.exe`" serve --config `"$InstallDir\config.yaml`""
$svc = Get-Service -Name 'Blacknet' -ErrorAction SilentlyContinue
if ($svc) {
    Write-Host "Service already exists — restarting."
    Restart-Service Blacknet
} else {
    sc.exe create Blacknet binPath= $exe start= auto DisplayName= "Blacknet DNS Filter" | Out-Null
    sc.exe description Blacknet "Self-hosted network-wide DNS ad and tracker blocker" | Out-Null
    sc.exe failure Blacknet reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
    Start-Service Blacknet
    Write-Host "Service installed and started."
}

Write-Host ""
Write-Host "Done. Dashboard: http://<this-pc>:$WebPort"
Write-Host "Next: reserve this PC's IP in your router and set the router's DNS to it."
