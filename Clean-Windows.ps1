function DisableService ($serviceName, $terminate = $true) {
    $service = Get-Item "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
    if ($service) {
        "Disabling service: $serviceName"
        $service | foreach {
            $commandLine = $_ | Get-ItemPropertyValue -Name ImagePath
            $processid = Get-WmiObject -Class Win32_Process |? CommandLine -eq $commandLine | Select-Object -ExpandProperty ProcessId
            if ($processid -and $terminate) {
                taskkill.exe /f /PID $processid
            }
            $_ | Set-ItemProperty -Name "Start" -Value ([ServiceStartType]::Disabled) -Force
        }
    }
}

function DisableScheduledTask ($taskName) {
    try {
        $task = Get-ScheduledTask -TaskName $taskName
        $task | Stop-ScheduledTask
        $task | Disable-ScheduledTask | Out-Null
    } catch {
        Write-Host "Cannot disable schedulded task $taskName"
    }
}

function RemoveAppxProvisionedPackage($packageName) {
    $pkg = Get-AppxProvisionedPackage -Online | ? PackageName -eq $packageName | select DisplayName, PackageName
    if ($pkg) {
        Write-Host $pkg.DisplayName

        Remove-AppxProvisionedPackage -Online -PackageName $pkg.PackageName

        if (Get-AppxPackage -AllUsers $pkg.DisplayName) {
            Write-Host "Also removing installed package"
            $removeInfos = (Get-AppxPackage -AllUsers $pkg.DisplayName | Remove-AppxPackage -AllUsers)
            if ($removeInfos.RestartNeeded) {
                Write-Host "You need to restart to apply changes"
            }
        } else {
            Write-Host "Seems the package was just provisioned, not installed."
        }
    } else {
        Write-Host "Cannot find this package"
    }
}

Clear-Host

# Telemetry
DisableService -serviceName "DiagTrack"
DisableService -serviceName "WdiSystemHost" -terminate $false

# OneDrive?
DisableService -serviceName "OneSyncSvc*"

# Push notification service
DisableService -serviceName "WpnService"
DisableService -serviceName "WpnUserService_*"

# Everything Xbox related
DisableService -serviceName "XblAuthManager"
DisableService -serviceName "XblGameSave"
DisableService -serviceName "XboxGipSvc"
DisableService -serviceName "XboxNetApiSvc"

# Everything MS-Edge related
DisableService -serviceName "edgeupdate"
DisableService -serviceName "edgeupdatem" 
DisableService -serviceName "MicrosoftEdgeElevationService"
DisableService -serviceName "uhssvc"

# Contact data
DisableService -serviceName "PimIndexMaintenanceSvc_*"

# Maps data
DisableService -serviceName "MapsBroker" -terminate $false

# Connect with Microsoft Account
DisableService -serviceName "wlidsvc" -terminate $false

# haptic screen service
DisableService -serviceName "TabletInputService" -terminate $true

# Windows Insider
DisableService -serviceName "wisvc"

# "Windows service to stream or record gameplay"
DisableService -serviceName "BcastDVRUserService"

#
Get-Service fdPHost | Stop-Service -Force | Set-Service -StartupType ([System.ServiceProcess.ServiceStartMode]::Disabled)

# NetBIOS resolution
Get-Service lmhosts | Stop-Service -Force | Set-Service -StartupType ([System.ServiceProcess.ServiceStartMode]::Disabled)

# Windows Error Reporting
Get-Service WerSvc | Stop-Service -Force | Set-Service -StartupType ([System.ServiceProcess.ServiceStartMode]::Disabled)

#--------------------------------------------------------
DisableScheduledTask( "MicrosoftEdgeUpdateTaskMachineCore" )
DisableScheduledTask( "MicrosoftEdgeUpdateTaskMachineUA" )
DisableScheduledTask( "OneDrive Reporting Task-*" )
DisableScheduledTask( "OneDrive Standalone Update Task-*" )
#---------------------------------------------------------------------------------------------------------
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftStickyNotes_3.6.73.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MSPaint_2019.729.2301.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MixedReality.Portal_2000.19081.1301.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Microsoft3DViewer_6.1908.2042.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ScreenSketch_2019.904.1644.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftOfficeHub_18.1903.1152.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Windows.Photos_2023.10030.27002.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsAlarms_2022.2302.4.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Office.OneNote_16001.12026.20112.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.SkypeApp_14.53.77.0_neutral_~_kzf8qxf38zg5c" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsFeedbackHub_2019.1111.2029.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.GetHelp_10.1706.13331.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.YourPhone_2019.430.2026.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsMaps_2019.716.2316.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Xbox.TCUI_1.23.28002.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxApp_48.49.31001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxGameOverlay_1.46.11001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxGamingOverlay_2.34.28001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Getstarted_8.2.22942.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxIdentityProvider_12.50.6001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ZuneMusic_2019.19071.19011.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ZuneVideo_2019.19071.19011.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.People_2019.305.632.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.549981C3F5F10_4.2204.13303.0_neutral_~_8wekyb3d8bbwe" ) # Cortana
# Disable PowerShell 2 to avoid downgrade attacks via ScriptBlocks
$restartNeeded = (Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart).RestartNeeded
$restartNeeded = $restartNeeded -or (Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart).RestartNeeded
$restartNeeded = $restartNeeded -or (Disable-WindowsOptionalFeature -Online -Remove -FeatureName Printing-XPSServices-Features -NoRestart).RestartNeeded

if ($restartNeeded) {
    Write-Host "A restart is needed"
}

# Drop everything in Windows Firewall by default
Get-NetFirewallProfile | Set-NetFirewallProfile -DefaultInboundAction "Block" -DefaultOutboundAction "Block"

# Remove all firewall rules 
Get-NetFirewallRule | Remove-NetFirewallRule

# Enable firewall logging
Get-NetFirewallProfile | Set-NetFirewallProfile -LogAllowed "True" -LogBlocked "True"

# Allow DHCP
New-NetFirewallRule -DisplayName "Allow DHCP" -Service "Dhcp" -RemotePort 67 -Action Allow -Protocol UDP -Direction Outbound

# Allow DNS
New-NetFirewallRule -DisplayName "Allow DNS" -Service "Dnscache" -RemotePort 53 -Action Allow -Protocol UDP -Direction Outbound

# Allow Firefox
New-NetFirewallRule -DisplayName "Allow Firefox (HTTP/HTTPS)" -Program "C:\Program Files\Mozilla Firefox\firefox.exe" -RemotePort 80,443 -Action Allow -Protocol TCP -Direction Outbound

# Allow Windows Update
New-NetFirewallRule -DisplayName "Allow Windows Update" -Service wuauserv -Action Allow -Protocol TCP -Direction Outbound

# Disable Win+V
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Name "DisabledHotkeys" -Value "V"

# Disable Windows Search Bing
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Name "BingSearchEnabled" -Value 0
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Name "CortanaConsent" -Value 0
