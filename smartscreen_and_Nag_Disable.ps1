#requires -Version 5.1

param (
    [switch]$Revert,
    [switch]$Confirm = $true
)

# Auto-Elevation Block
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Elevating privileges..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $(if ($Revert) { '-Revert' }) $(if (-not $Confirm) { '-Confirm:$false' })"
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "Elevation canceled." -ForegroundColor Red
    }
    exit
}

# Check Windows Version
$osVersion = [Environment]::OSVersion.Version
if ($osVersion.Major -lt 10 -or ($osVersion.Major -eq 10 -and $osVersion.Build -lt 22000)) {
    Write-Host "This script is optimized for Windows 11 (build 22000+). Aborting." -ForegroundColor Red
    exit
}

# Warning and Confirmation
Write-Host "WARNING: Disabling SmartScreen reduces security against malicious files. Proceed at your own risk." -ForegroundColor Yellow
if ($Confirm -and -not $Revert) {
    $response = Read-Host "Apply tweaks? (Y/N)"
    if ($response -inotlike "Y*") { exit }
} elseif ($Confirm -and $Revert) {
    $response = Read-Host "Revert tweaks? (Y/N)"
    if ($response -inotlike "Y*") { exit }
}

$logPath = "$env:TEMP\SmartScreenTweaks.log"
Write-Host ("{0} SmartScreen and Edge friction-removal tweaks..." -f $(if ($Revert) { "Reverting" } else { "Applying" })) -ForegroundColor Cyan
Add-Content -Path $logPath -Value ("[{0}] Starting {1} operation" -f (Get-Date), $(if ($Revert) { "revert" } else { "apply" }))

function Set-RegistryValue {
    param (
        [string]$Path,
        [string]$Name,
        [string]$Type,
        $Value,
        [switch]$Revert
    )
    try {
        if (-not (Test-Path $Path)) {
            New-Item -Path $Path -Force | Out-Null
        }
        $currentValue = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue).$Name
        if ($Revert) {
            if ($null -ne $currentValue) {
                Remove-ItemProperty -Path $Path -Name $Name -Force -ErrorAction SilentlyContinue
                Write-Verbose "Reverted: ${Path}\${Name}"
                Add-Content -Path $logPath -Value "Reverted: ${Path}\${Name}"
            }
        } else {
            if ($currentValue -ne $Value) {
                New-ItemProperty -Path $Path -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null
                Write-Verbose "Set: ${Path}\${Name} = $Value"
                Add-Content -Path $logPath -Value "Set: ${Path}\${Name} = $Value"
            } else {
                Write-Verbose "Already set: ${Path}\${Name}"
            }
        }
    } catch {
        Write-Host "Error modifying ${Path}\${Name}: $_" -ForegroundColor Red
        Add-Content -Path $logPath -Value "Error: ${Path}\${Name} - $_"
    }
}

# Disable SmartScreen (Windows / Store Apps)
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type "String" -Value "Off" -Revert:$Revert
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type "DWord" -Value 1 -Revert:$Revert
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "ScanWithAntiVirus" -Type "DWord" -Value 1 -Revert:$Revert

# Disable SmartScreen for EXE Reputation
Set-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableSmartScreen" -Type "DWord" -Value 0 -Revert:$Revert

# Disable Attachment Manager Zone Tags (Optional)
Set-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" -Name "SaveZoneInformation" -Type "DWord" -Value 1 -Revert:$Revert

# Microsoft Edge – Disable SmartScreen
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Type "DWord" -Value 0 -Revert:$Revert
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenPuaEnabled" -Type "DWord" -Value 0 -Revert:$Revert

# Microsoft Edge – Disable Download Reputation Checks
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DownloadRestrictions" -Type "DWord" -Value 0 -Revert:$Revert
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverride" -Type "DWord" -Value 0 -Revert:$Revert
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PreventSmartScreenPromptOverrideForFiles" -Type "DWord" -Value 0 -Revert:$Revert

# Microsoft Edge – Allow All Downloads Without Warnings
Set-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AllowUnsafeDownloads" -Type "DWord" -Value 1 -Revert:$Revert  # Note: This key might not exist natively; revert removes it if set.

Write-Host ("All SmartScreen layers {0} and Edge download friction {1}." -f $(if ($Revert) { "re-enabled" } else { "disabled" }), $(if ($Revert) { "restored" } else { "removed" })) -ForegroundColor Green
Write-Host "Log saved to: $logPath" -ForegroundColor Gray
Write-Host "Some changes may require a restart or logoff to take effect." -ForegroundColor Yellow