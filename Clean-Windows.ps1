# Check if host has Internet access
$hasInternet = (Test-NetConnection -ComputerName 1.1.1.1).PingSucceeded

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
Get-Service DiagTrack | Stop-Service -Force | Set-Service -StartupType Disabled
Get-Service WdiSystemHost | Stop-Service -Force | Set-Service -StartupType Disabled

# OneDrive?
DisableService -serviceName "OneSyncSvc*"

# Push notification service
Get-Service WpnService | Stop-Service -Force | Set-Service -StartupType Disabled
Get-Service WpnUserService_* | Stop-Service -Force | Set-Service -StartupType Disabled

# Everything Xbox related
Get-Service | ? -FilterScript { ($_.Name -like "Xbl*") -or ($_.Name -like "*xbox*") } | foreach { sc.exe delete $_.Name }

# Everything MS-Edge related
Get-Service edgeupdate | Stop-Service -Force | Set-Service -StartupType Disabled
Get-Service edgeupdatem | Stop-Service -Force | Set-Service -StartupType Disabled
Get-Service MicrosoftEdgeElevationService | Stop-Service -Force | Set-Service -StartupType Disabled
#DisableService -serviceName "uhssvc"

# Contact data
Get-Service PimIndexMaintenanceSvc_* | Stop-Service -Force | Set-Service -StartupType Disabled

# Maps data
Get-Service MapsBroker | Stop-Service -Force | Set-Service -StartupType Disabled

# Connect with Microsoft Account
Get-Service wlidsvc | Stop-Service -Force | Set-Service -StartupType Disabled

# haptic screen service
#DisableService -serviceName "TabletInputService" -terminate $true

# Windows Insider
Get-Service wisvc | Stop-Service -Force | Set-Service -StartupType Disabled

# "Windows service to stream or record gameplay"
Get-Service BcastDVRUserService | Stop-Service -Force | Set-Service -StartupType Disabled

Get-Service CDPUserSvc_* | Stop-Service -Force | Set-Service -StartupType Disabled

#
Get-Service fdPHost | Stop-Service -Force | Set-Service -StartupType Disabled 

# NetBIOS resolution
Get-Service lmhosts | Stop-Service -Force | Set-Service -StartupType Disabled 

# Windows Error Reporting
Get-Service WerSvc | Stop-Service -Force | Set-Service -StartupType Disabled 

# Disable Print Spooler
Get-Service Spooler | Stop-Service -Force | Set-Service -StartupType Disabled 

# Disable "IP Helper" (IPv6 support)
Get-Service iphlpsvc | Stop-Service -Force | Set-Service -StartupType Disabled 

# Internet Connection Sharing (ICS)
Get-Service SharedAccess | Stop-Service -Force | Set-Service -StartupType Disabled 

# Telephony API
Get-Service tapisrv | Stop-Service -Force | Set-Service -StartupType Disabled 

#Get-Service WinHttpAutoProxySvc | Stop-Service -Force | Set-Service -StartupType Disabled 

Get-Service CDPSvc | Stop-Service -Force | Set-Service -StartupType Disabled

Get-Service DPS | Stop-Service -Force | Set-Service -StartupType Disabled

# Windows Store installer service 
Get-Service InstallService | Stop-Service -Force | Set-Service -StartupType Disabled

# SSTP connection support service
Get-Service SstpSvc | Stop-Service -Force | Set-Service -StartupType Disabled

# Windows Image Acquisition
Get-Service stisvc | Stop-Service -Force | Set-Service -StartupType Disabled

# "Token Broker is used to manage permissions for the Windows App Store"
Get-Service TokenBroker | Stop-Service -Force | Set-Service -StartupType Disabled 

# Distribution optimization
Get-Service DoSvc | Stop-Service -Force | Set-Service -StartupType Disabled 

# Chip Cards
Get-Service SCardSvr | Stop-Service -Force | Set-Service -StartupType Disabled

# Web accounts
Get-Service TokenBroker | Stop-Service -Force | Set-Service -StartupType Disabled

# IPv6 support
Get-Service iphlpsvc | Stop-Service -Force | Set-Service -StartupType Disabled

#--------------------------------------------------------
DisableScheduledTask( "MicrosoftEdgeUpdateTaskMachineCore" )
DisableScheduledTask( "MicrosoftEdgeUpdateTaskMachineUA" )
DisableScheduledTask( "OneDrive Reporting Task-*" )
DisableScheduledTask( "OneDrive Standalone Update Task-*" )
#---------------------------------------------------------------------------------------------------------
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftStickyNotes_3.6.73.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MSPaint_2019.729.2301.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Wallet_2.4.18324.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MixedReality.Portal_2000.21051.1282.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Microsoft3DViewer_6.1908.2042.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ScreenSketch_2019.904.1644.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftOfficeHub_18.1903.1152.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftSolitaireCollection_4.4.8204.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Windows.Photos_2019.19071.12548.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsAlarms_2022.2302.4.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Office.OneNote_16001.12026.20112.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.SkypeApp_14.53.77.0_neutral_~_kzf8qxf38zg5c" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsFeedbackHub_2019.1111.2029.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.GetHelp_10.2403.20861.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.YourPhone_1.24062.101.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsMaps_2019.716.2316.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Xbox.TCUI_1.23.28002.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxApp_48.49.31001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxGameOverlay_1.46.11001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxGamingOverlay_2.34.28001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxSpeechToTextOverlay_1.21.13002.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Getstarted_2021.2312.1.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.BingWeather_4.25.20211.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxIdentityProvider_12.50.6001.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ZuneMusic_2019.19071.19011.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.ZuneVideo_2019.19071.19011.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.People_2019.305.632.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.549981C3F5F10_1.1911.21713.0_neutral_~_8wekyb3d8bbwe" ) # Cortana
# Disable PowerShell 2 to avoid downgrade attacks via ScriptBlocks
$restartNeeded = (Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart).RestartNeeded
$restartNeeded = $restartNeeded -or (Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart).RestartNeeded
$restartNeeded = $restartNeeded -or (Disable-WindowsOptionalFeature -Online -Remove -FeatureName Printing-XPSServices-Features -NoRestart).RestartNeeded

if ($restartNeeded) {
    Write-Host "A restart is needed"
}

# ----- Remove all firewall rules ------
Get-NetFirewallRule | Remove-NetFirewallRule

# ------------ Firewall rules ------------ 
New-NetFirewallRule -DisplayName "msedge.exe" -Program "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "smartscreen.exe" -Program "C:\Windows\System32\smartscreen.exe" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "SystemSettings.exe" -Program "C:\Windows\ImmersiveControlPanel\SystemSettings.exe" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "explorer.exe" -Program "%SystemRoot%\explorer.exe" -Direction Outbound -Action Block
New-NetFirewallRule -DisplayName "WWAHost.exe" -Program "C:\Windows\System32\WWAHost.exe" -Direction Outbound -Action Block

# ------------ Block Microsoft Spy addresses ------------
$ipList = Invoke-WebRequest -UseBasicParsing -Uri "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/firewall/spy.txt" | Select-Object -ExpandProperty Content

$ipList = $ipList -split "\r?\n"

$ipList | Where-Object {
    $_ -notmatch "^\s*(#|$)" -and `
    (New-NetFirewallRule -DisplayName "BlockSpy_$($_)" -Enabled True -RemoteAddress $_ -Direction Outbound -Action Block)
}

# ------------ Disable Win+V ------------
New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Type ([Microsoft.Win32.RegistryValueKind]::String) -Name "DisabledHotkeys" -Value "V"

# Stop explorer.exe to apply changes ; it should restart automatically
Stop-Process -Name explorer

# Disable Windows Search Bing
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Name "BingSearchEnabled" -Value 0
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Type ([Microsoft.Win32.RegistryValueKind]::DWord) -Name "CortanaConsent" -Value 0

# Disable Windows Defender scheduled tasks
Get-ScheduledTask “Windows Defender Cache Maintenance” | Disable-ScheduledTask
Get-ScheduledTask “Windows Defender Cleanup” | Disable-ScheduledTask
Get-ScheduledTask “Windows Defender Scheduled Scan” | Disable-ScheduledTask
Get-ScheduledTask “Windows Defender Verification” | Disable-ScheduledTask

New-Item -Type Directory "HKLM:\Software\Policies\Microsoft\Edge"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name EnableMediaRouter -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name EnableMDNS -Value 0 -Force
