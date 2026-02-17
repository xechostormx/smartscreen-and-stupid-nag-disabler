# ============================================
#  Auto‑Elevation Block
# ============================================
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
    [Security.Principal.WindowsBuiltInRole] "Administrator"))
{
    Write-Host "Elevating privileges..." -ForegroundColor Yellow
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = "powershell.exe"
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    $psi.Verb = "runas"
    try {
        [System.Diagnostics.Process]::Start($psi) | Out-Null
    } catch {
        Write-Host "Elevation canceled." -ForegroundColor Red
    }
    exit
}

Write-Host "Applying SmartScreen and Edge friction‑removal tweaks..." -ForegroundColor Cyan

# ============================================
# Disable SmartScreen (Windows / Store Apps)
# ============================================
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v ScanWithAntiVirus /t REG_DWORD /d 1 /f

# ============================================
# Disable SmartScreen for EXE Reputation
# ============================================
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableSmartScreen /t REG_DWORD /d 0 /f

# ============================================
# Disable Attachment Manager Zone Tags (Optional)
# ============================================
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v SaveZoneInformation /t REG_DWORD /d 1 /f

# ============================================
# Microsoft Edge – Disable SmartScreen
# ============================================
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SmartScreenEnabled /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v SmartScreenPuaEnabled /t REG_DWORD /d 0 /f

# ============================================
# Microsoft Edge – Disable Download Reputation Checks
# ============================================
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DownloadRestrictions /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PreventSmartScreenPromptOverride /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v PreventSmartScreenPromptOverrideForFiles /t REG_DWORD /d 0 /f

# ============================================
# Microsoft Edge – Allow All Downloads Without Warnings
# ============================================
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v AllowUnsafeDownloads /t REG_DWORD /d 1 /f

Write-Host "All SmartScreen layers disabled and Edge download friction removed." -ForegroundColor Green
