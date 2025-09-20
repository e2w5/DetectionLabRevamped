#some tweaks i like, some are taken from ChrisTitus WinUtil
Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Enable End Task With Right Click"
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings"
      $name = "TaskbarEndTask"
      $value = 1

      # Ensure the registry key exists
      if (-not (Test-Path $path)) {
        New-Item -Path $path -Force | Out-Null
      }

      # Set the property, creating it if it doesn't exist
      New-ItemProperty -Path $path -Name $name -PropertyType DWord -Value $value -Force | Out-Null

write-host "$('[{0:HH:mm}]' -f (Get-Date)) Set Services to Manual"
# Define services and desired startup types directly in the script
$services = @(
    @{"Name" = "AJRouter"; "StartupType" = "Disabled"},
    @{"Name" = "ALG"; "StartupType" = "Manual"},
    @{"Name" = "AppIDSvc"; "StartupType" = "Manual"},
    @{"Name" = "BITS"; "StartupType" = "AutomaticDelayedStart"},
    @{"Name" = "WSearch"; "StartupType" = "AutomaticDelayedStart"},
    @{"Name" = "AppXSvc"; "StartupType" = "Manual"},
    @{"Name" = "RpcSs"; "StartupType" = "Automatic"},
    @{"Name" = "Dnscache"; "StartupType" = "Automatic"},
    @{"Name" = "Tcpip"; "StartupType" = "Automatic"}

    )
# Map simplified types to actual PowerShell-compatible settings
function Convert-StartupType {
    param ([string]$type)
    switch ($type) {
        "Automatic" { return "Automatic" }
        "Manual"    { return "Manual" }
        "Disabled"  { return "Disabled" }
        "AutomaticDelayedStart" { return "AutomaticDelayedStart" }
        default     { return $null }
    }
}

# Main logic
foreach ($svc in $services) {
    $serviceName = $svc.Name
    $startupType = Convert-StartupType $svc.StartupType

    if (-not $startupType) {
        Write-Warning "Unknown StartupType '$($svc.StartupType)' for service $serviceName"
        continue
    }
try {
    if ($serviceName -like "*`*") {
        Get-WmiObject Win32_Service | Where-Object { $_.Name -like $serviceName } | ForEach-Object {
            sc.exe config $_.Name start= $startupType | Out-Null
            Write-Output "Set service '$($_.Name)' to '$startupType'"
        }
    } elseif ($startupType -eq "AutomaticDelayedStart") {
        Set-Service -Name $serviceName -StartupType Automatic -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name "DelayedAutoStart" -Value 1
        Write-Output "Set service '$serviceName' to Automatic (Delayed Start)"
    } else {
        Set-Service -Name $serviceName -StartupType $startupType -ErrorAction Stop
        Write-Output "Set service '$serviceName' to '$startupType'"
    }
} catch {
    Write-Warning "Failed to update ${serviceName}: $($_.Exception.Message)"
}


}


Write-Host "Remove Copilot"
dism /online /remove-package /package-name:Microsoft.Windows.Copilot

Write-Host "Edge Debloat"
# PowerShell script to create/modify Edge policy registry keys
Write-Output "Applying Edge registry policy tweaks..."
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate" -Name "CreateDesktopShortcutDefault" -Type DWord -Value 0
Write-Output "Set CreateDesktopShortcutDefault to 0 in HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeEnhanceImagesEnabled" -Type DWord -Value 0
Write-Output "Set EdgeEnhanceImagesEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "PersonalizationReportingEnabled" -Type DWord -Value 0
Write-Output "Set PersonalizationReportingEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowRecommendationsEnabled" -Type DWord -Value 0
Write-Output "Set ShowRecommendationsEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "HideFirstRunExperience" -Type DWord -Value 1
Write-Output "Set HideFirstRunExperience to 1 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "UserFeedbackAllowed" -Type DWord -Value 0
Write-Output "Set UserFeedbackAllowed to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ConfigureDoNotTrack" -Type DWord -Value 1
Write-Output "Set ConfigureDoNotTrack to 1 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "AlternateErrorPagesEnabled" -Type DWord -Value 0
Write-Output "Set AlternateErrorPagesEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeCollectionsEnabled" -Type DWord -Value 0
Write-Output "Set EdgeCollectionsEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeFollowEnabled" -Type DWord -Value 0
Write-Output "Set EdgeFollowEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeShoppingAssistantEnabled" -Type DWord -Value 0
Write-Output "Set EdgeShoppingAssistantEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "MicrosoftEdgeInsiderPromotionEnabled" -Type DWord -Value 0
Write-Output "Set MicrosoftEdgeInsiderPromotionEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "ShowMicrosoftRewards" -Type DWord -Value 0
Write-Output "Set ShowMicrosoftRewards to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WebWidgetAllowed" -Type DWord -Value 0
Write-Output "Set WebWidgetAllowed to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "DiagnosticData" -Type DWord -Value 0
Write-Output "Set DiagnosticData to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "EdgeAssetDeliveryServiceEnabled" -Type DWord -Value 0
Write-Output "Set EdgeAssetDeliveryServiceEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "CryptoWalletEnabled" -Type DWord -Value 0
Write-Output "Set CryptoWalletEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "WalletDonationEnabled" -Type DWord -Value 0
Write-Output "Set WalletDonationEnabled to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Edge"

# PowerShell script to set WiFi policy registry keys
Write-Output "Applying WiFi policy registry tweaks..."

New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Write-Output "Set Value to 0 in HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"

New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
Write-Output "Set Value to 0 in HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"

Write-Host "Disable Hibernation"
powercfg.exe /hibernate off


Write-Host "Disable location tracking"
Write-Output "Applying location/sensor/maps registry policy changes..."

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
Write-Output "Set Value to "Deny" in HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location"

New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Write-Output "Set SensorPermissionState to 0 in HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"

New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
Write-Output "Set Status to 0 in HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"

New-Item -Path "HKLM:\SYSTEM\Maps" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
Write-Output "Set AutoUpdateEnabled to 0 in HKLM:\SYSTEM\Maps"

Write-Host "Disable GameDVR"
# PowerShell script to configure GameDVR-related registry settings
Write-Output "Applying GameDVR tweaks..."

New-Item -Path "HKCU:\System\GameConfigStore" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -Type DWord -Value 2
Write-Output "Set GameDVR_FSEBehavior to 2 in HKCU:\System\GameConfigStore"

Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Type DWord -Value 0
Write-Output "Set GameDVR_Enabled to 0 in HKCU:\System\GameConfigStore"

Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -Type DWord -Value 1
Write-Output "Set GameDVR_HonorUserFSEBehaviorMode to 1 in HKCU:\System\GameConfigStore"

Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_EFSEFeatureFlags" -Type DWord -Value 0
Write-Output "Set GameDVR_EFSEFeatureFlags to 0 in HKCU:\System\GameConfigStore"

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0
Write-Output "Set AllowGameDVR to 0 in HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"

write-host "Disable Storage Sense"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Name "01" -Value 0 -Type Dword -Force

$OneDrivePath = $($env:OneDrive)
Write-Host "Removing OneDrive"
$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OneDriveSetup.exe"
if (Test-Path $regPath) {
    $OneDriveUninstallString = Get-ItemPropertyValue "$regPath" -Name "UninstallString"
    $OneDriveExe, $OneDriveArgs = $OneDriveUninstallString.Split(" ")
    Start-Process -FilePath $OneDriveExe -ArgumentList "$OneDriveArgs /silent" -NoNewWindow -Wait
} else {
    Write-Host "Onedrive dosn't seem to be installed anymore" -ForegroundColor Red
    return
}
# Check if OneDrive got Uninstalled
if (-not (Test-Path $regPath)) {
Write-Host "Copy downloaded Files from the OneDrive Folder to Root UserProfile"
Start-Process -FilePath powershell -ArgumentList "robocopy '$($OneDrivePath)' '$($env:USERPROFILE.TrimEnd())\' /mov /e /xj" -NoNewWindow -Wait

Write-Host "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
reg delete "HKEY_CURRENT_USER\Software\Microsoft\OneDrive" /f
# check if directory is empty before removing:
If ((Get-ChildItem "$OneDrivePath" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$OneDrivePath"
}

Write-Host "Remove Onedrive from explorer sidebar"
Set-ItemProperty -LiteralPath "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0
Set-ItemProperty -LiteralPath "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Name "System.IsPinnedToNameSpaceTree" -Value 0

Write-Host "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Host "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Host "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

# Add Shell folders restoring default locations
Write-Host "Shell Fixing"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "AppData" -Value "$env:userprofile\AppData\Roaming" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Cache" -Value "$env:userprofile\AppData\Local\Microsoft\Windows\INetCache" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Cookies" -Value "$env:userprofile\AppData\Local\Microsoft\Windows\INetCookies" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Favorites" -Value "$env:userprofile\Favorites" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "History" -Value "$env:userprofile\AppData\Local\Microsoft\Windows\History" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Local AppData" -Value "$env:userprofile\AppData\Local" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Music" -Value "$env:userprofile\Music" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Video" -Value "$env:userprofile\Videos" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "NetHood" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Network Shortcuts" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "PrintHood" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Printer Shortcuts" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Programs" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Recent" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Recent" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "SendTo" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\SendTo" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Start Menu" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Startup" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Templates" -Value "$env:userprofile\AppData\Roaming\Microsoft\Windows\Templates" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{374DE290-123F-4565-9164-39C4925E467B}" -Value "$env:userprofile\Downloads" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Desktop" -Value "$env:userprofile\Desktop" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "My Pictures" -Value "$env:userprofile\Pictures" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "Personal" -Value "$env:userprofile\Documents" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{F42EE2D3-909F-4907-8871-4C22FC0BF756}" -Value "$env:userprofile\Documents" -Type ExpandString
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders" -Name "{0DDD015D-B06C-45D5-8C4C-F59713854639}" -Value "$env:userprofile\Pictures" -Type ExpandString
Write-Host "Restarting explorer"
taskkill.exe /F /IM "explorer.exe"
Start-Process "explorer.exe"

Write-Host "Waiting for explorer to complete loading"
Write-Host "Please Note - The OneDrive folder at $OneDrivePath may still have items in it. You must manually delete it, but all the files should already be copied to the base user folder."
Write-Host "If there are Files missing afterwards, please Login to Onedrive.com and Download them manually" -ForegroundColor Yellow
Start-Sleep 5
} else {
Write-Host "Something went Wrong during the Unistallation of OneDrive" -ForegroundColor Red
}
