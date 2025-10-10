# Configuration
$BlockedProcessesOutbound = @(
    "$env:SystemRoot\System32\wermgr.exe"
    "$env:SystemRoot\System32\werfault.exe"
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    "${env:ProgramFiles(x86)}\Microsoft\edgeupdate\microsoftedgeupdate.exe"
    "$env:SystemRoot\System32\smartscreen.exe"
    "$env:SystemRoot\ImmersiveControlPanel\SystemSettings.exe"
    "$env:SystemRoot\System32\WWAHost.exe"
    "$env:SystemRoot\explorer.exe"
    "$env:SystemRoot\System32\mousocoreworker.exe"
    "$env:SystemRoot\immersivecontrolpanel\systemsettings.exe",
    "${env:ProgramFiles(x86)}\steam\steamerrorreporter64.exe"
)

$ServicesToDelete = @(
    "DiagTrack" # Telemetry
    "edgeupdate"
    "edgeupdatem"
    "MicrosoftEdgeElevationService"
    "AsusSystemDiagnosis"
    "wlidsvc"
    "wisvc" # Windows Insider
    "OneSyncSvc_*"
    "iphlpsvc" # IPv6 support
    "WerSvc" # Windows Error Reporting
    "SCardSvr" # Chip cards
    "lmhosts" # NetBIOS resolution
)

reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Hidden /t REG_DWORD /d 1 /f
reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

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

Get-Service -Name $ServicesToDelete 2>$null | Foreach-Object { sc.exe stop $_.Name; sc.exe delete $_.Name } 

# Telemetry
Get-Service WdiSystemHost | Stop-Service -Force | Set-Service -StartupType Disabled

# OneDrive?
DisableService -serviceName "OneSyncSvc*"

# Push notification service
Get-Service WpnService | Stop-Service -Force | Set-Service -StartupType Disabled
Get-Service WpnUserService_* | Stop-Service -Force | Set-Service -StartupType Disabled

# Everything Xbox related
Get-Service | ? -FilterScript { ($_.Name -like "Xbl*") -or ($_.Name -like "*xbox*") } | foreach { sc.exe delete $_.Name }

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

# Disable Print Spooler
Get-Service Spooler | Stop-Service -Force | Set-Service -StartupType Disabled 

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

# Web accounts
Get-Service TokenBroker | Stop-Service -Force | Set-Service -StartupType Disabled

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
RemoveAppxProvisionedPackage ( "Clipchamp.Clipchamp_2.2.8.0_neutral_~_yxz26nhyzhsrt" )
RemoveAppxProvisionedPackage ( "Microsoft.BingNews_2022.507.446.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Windows.DevHome_2024.703.849.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Todos_2022.507.447.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.OutlookForWindows_1.2024.717.400_x64__8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.Paint_11.2404.1020.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.PowerAutomateDesktop_2022.507.446.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "MicrosoftTeams_24124.2402.2858.5617_x64__8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "MicrosoftCorporationII.QuickAssist_2022.507.446.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsSoundRecorder_2021.2103.28.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "MicrosoftWindows.CrossDevice_1.24062.51.0_neutral_~_cw5n1h2txyewy" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsAlarms_2021.2403.8.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.WindowsNotepad_2022.507.446.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "microsoft.windowscommunicationsapps_16005.14326.22019.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.XboxGamingOverlay_7.124.5142.0_neutral_~_8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.MicrosoftEdge.Stable_127.0.2651.86_neutral__8wekyb3d8bbwe" )
RemoveAppxProvisionedPackage ( "Microsoft.GamingApp_2407.1001.1.0_neutral_~_8wekyb3d8bbwe" )

# Disable PowerShell 2 to avoid downgrade attacks via ScriptBlocks
Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart
Disable-WindowsOptionalFeature -Online -Remove -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart
Disable-WindowsOptionalFeature -Online -Remove -FeatureName Printing-XPSServices-Features -NoRestart

# ----- Remove all firewall rules ------
Get-Netfirewallrule | Where-Object Description -eq "CREATED_FROM_WINDOWS_CLEAN_SCRIPT" | Remove-NetFirewallRule

# ------------ Block specified processes outbound traffic ------------ 
$BlockedProcessesOutbound | foreach {
    New-NetFirewallRule -Direction Outbound -Action Block -Program $_ -DisplayName (Split-Path "$_" -Leaf) -Description "CREATED_FROM_WINDOWS_CLEAN_SCRIPT"
}

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
