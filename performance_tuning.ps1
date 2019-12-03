# HSO PERFORMANCE TUNING SETTINGS 

# Ref Document : CIS Microsoft Windows Server 2016 RTM Release 1607 Benchmark v1.1.0

# 18.1.2.2 : Ensure 'Allow input personalization' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name InputPersonalization
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization -Name AllowInputPersonalization -Value 0 -PropertyType "DWord"

# 18.1.3 : Ensure 'Allow Online Tips' is set to 'Disabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer -Name AllowOnlineTips -Value 0 -PropertyType "DWord"

# 18.5.19.2.1 : Disable IPv6
New-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters -Name DisabledComponents -Value 255 -PropertyType "DWord"

# 18.5.20.1 : Ensure 'Configuration of wireless settings using Windows Connect Now' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WCN
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN -Name Registrars
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -Name EnableRegistrars -Value 0 -PropertyType "DWord"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -Name DisableUPnPRegistrar -Value 0 -PropertyType "DWord"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -Name DisableInBand802DOT11Registrar -Value 0 -PropertyType "DWord"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -Name DisableFlashConfigRegistrar -Value 0 -PropertyType "DWord"
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars -Name DisableWPDRegistrar -Value 0 -PropertyType "DWord" 

# 18.8.22.1.3 : Ensure 'Turn off handwriting recognition error reporting' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name HandwritingErrorReports
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports -Name PreventHandwritingErrorReports -Value 1 -PropertyType "DWord"

# 18.8.22.1.8 : Ensure 'Turn off Search Companion content file updates' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name SearchCompanion
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\SearchCompanion -Name DisableContentFileUpdates -Value 1 -PropertyType "DWord"

# 18.8.22.1.11 : Ensure 'Turn off the Windows Messenger Customer Experience Improvement Program' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name Messenger
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Messenger -Name Client
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Messenger\Client -Name CEIP -Value 2 -PropertyType "DWord"

# 18.8.22.1.12 : Ensure 'Turn off Windows Customer Experience Improvement Program' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name SQMClient
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\SQMClient -Name Windows
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows -Name CEIPEnable -Value 0 -PropertyType "DWord"

# 18.8.22.1.13 : Ensure 'Turn off Windows Error Reporting' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name "Windows Error Reporting"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' -Name Disabled -Value 1 -PropertyType "DWord"
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name PCHealth
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\PCHealth -Name ErrorReporting
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting -Name DoReport -Value 0 -PropertyType "DWord"

# 18.8.44.5.1 : Ensure 'Microsoft Support Diagnostic Tool: Turn on MSDT interactive communication with support provider' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name ScriptedDiagnosticsProvider
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider -Name Policy
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy -Name DisableQueryRemoteServer -Value 0 -PropertyType "DWord"

# 18.8.44.11.1 : Ensure 'Enable/Disable PerfTrack' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name WDI
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI -Name "{9c5a40da-b965-4fc3-8781-88dd50a6299d}" 
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}' -Name ScenarioExecutionEnabled -Value 0 -PropertyType "DWord"

# 18.8.46.1 : Ensure 'Turn off the advertising ID' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name AdvertisingInfo
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo -Name DisabledByGroupPolicy -Value 1 -PropertyType "DWord"

# 18.8.49.1.1 : Ensure 'Enable Windows NTP Client' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name W32Time
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time -Name TimeProviders
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders -Name NtpClient
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient -Name Enabled -Value 1 -PropertyType "DWord"

# 18.8.49.1.2 : Ensure 'Enable Windows NTP Server' is set to 'Disabled' (MS only)
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders -Name NtpServer
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpServer -Name Enabled -Value 0 -PropertyType "DWord"

# 18.9.4.1 : Ensure 'Allow a Windows app to share application data between users' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion -Name AppModel
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel -Name StateManager
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager -Name AllowSharedLocalAppData -Value 0 -PropertyType "DWord"

# 18.9.13.1 : Ensure 'Turn off Microsoft consumer experiences' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name CloudContent
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent -Name DisableWindowsConsumerFeatures -Value 1 -PropertyType "DWord"

# 18.9.16.3 : Ensure 'Disable pre-release features or settings' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name PreviewBuilds
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds -Name EnableConfigFlighting -Value 0 -PropertyType "DWord"

# 18.9.16.4 : Ensure 'Do not show feedback notifications' is set to 'Enabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection -Name DoNotShowFeedbackNotifications -Value 1 -PropertyType "DWord"

# 18.9.39.2 : Ensure 'Turn off location' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name LocationAndSensors
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors -Name DisableLocation -Value 1 -PropertyType "DWord"

# 18.9.43.1 : Ensure 'Allow Message Service Cloud Sync' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name Messaging
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Messaging -Name AllowMessageSync -Value 0 -PropertyType "DWord"

# 18.9.52.1 : Ensure 'Prevent the usage of OneDrive for file storage' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name OneDrive
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive -Name DisableFileSyncNGSC -Value 1 -PropertyType "DWord"

# 18.9.58.3.11.1 : Ensure 'Do not delete temp folders upon exit' is set to 'Disabled'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name DeleteTempDirsOnExit -Value 1 -PropertyType "DWord"

# 18.9.58.3.11.2 : Ensure 'Do not use temporary folders per session' is set to 'Disabled'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name PerSessionTempDir -Value 1 -PropertyType "DWord"

# 18.9.59.1 : Ensure 'Prevent downloading of enclosures' is set to 'Enabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name "Internet Explorer"
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer' -Name Feeds
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Feeds' -Name DisableEnclosureDownload -Value 1 -PropertyType "DWord"

# 18.9.60.2 : Ensure 'Allow Cloud Search' is set to 'Enabled: Disable Cloud Search'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows -Name "Windows Search"
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name AllowCloudSearch -Value 0 -PropertyType "DWord"

# 18.9.76.3.1 : Ensure 'Configure local setting override for reporting to Microsoft MAPS' is set to 'Disabled'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name Spynet
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name LocalSettingOverrideSpynetReporting -Value 0 -PropertyType "DWord"

# 18.9.76.3.2 : Ensure 'Join Microsoft MAPS' is set to 'Disabled'
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet' -Name SpynetReporting -Value 0 -PropertyType "DWord"

# 18.9.76.9.1 : Ensure 'Configure Watson events' is set to 'Disabled'
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name Reporting
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Reporting' -Name DisableGenericRePorts -Value 1 -PropertyType "DWord"

# 18.9.84.1 : Ensure 'Allow suggested apps in Windows Ink Workspace' is set to 'Disabled'
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft -Name WindowsInkWorkspace
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace -Name AllowSuggestedAppsInWindowsInkWorkspace -Value 0 -PropertyType "DWord"

#-------------------------------------------------------------------------------------------------

# Ref Document : CIS Google Chrome Benchmark v2.0.0

# 1.2 : Ensure 'Continue running background apps when Google Chrome is closed' is set to 'Disabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name BackgroundModeEnabled -Value 0 -PropertyType "DWord"

# 3.6 : Ensure 'Control how Chrome Cleanup reports data to Google' is set to 'Disabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name ChromeCleanupReportingEnabled -Value 0 -PropertyType "DWord"

# 3.13 : Ensure 'Disable synchronization of data with Google' is set to 'Enabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name SyncDisabled -Value 1 -PropertyType "DWord"

# 3.15 : Ensure 'Enable URL-keyed anonymized data collection' is set to 'Disabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name UrlKeyedAnonymizedDataCollectionEnabled -Value 0 -PropertyType "DWord"

# 5.3 : Ensure 'Enable AutoFill for credit cards' is set to 'Disabled'
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Google\Chrome -Name AutofillCreditCardEnabled -Value 0 -PropertyType "DWord"

#-------------------------------------------------------------------------------------------------

# Stopping and Disabling Windows Services

# IP Helper
Stop-Service iphlpsvc
Set-Service iphlpsvc -StartupType Disabled

# Downloaded Maps Manager
Stop-Service MapsBroker
Set-Service MapsBroker -StartupType Disabled

# Diagnostic Policy Service
Stop-Service DPS
Set-Service DPS -StartupType Disabled

# Windows Font Cache Service
Stop-Service FontCache
Set-Service FontCache -StartupType Disabled

# Google Update Service (gupdate)
Stop-Service gupdate
Set-Service gupdate -StartupType Disabled

# User Access Logging Service
Stop-Service UALSVC
Set-Service UALSVC -StartupType Disabled

# Quality Windows Audio Video Experience
Stop-Service QWAVE
Set-Service QWAVE -StartupType Disabled

# Power
Stop-Service Power
Set-Service Power -StartupType Disabled

# Program Compatibility Assistant Service
Stop-Service PcaSvc
Set-Service PcaSvc -StartupType Disabled

# Shell Hardware Detection
Stop-Service ShellHWDetection
Set-Service ShellHWDetection -StartupType Disabled

# Sync Host
$suffix = Get-Service '*_*' | Select-Object Name | ForEach-Object { $_.Name.Split('_')[-1] } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1 -ExpandProperty Name
$serviceOneSync = Write-Output "OneSyncSvc_$suffix"
Stop-Service $serviceOneSync

# Print Spooler
#Stop-Service Spooler
#Set-Service Spooler -StartupType Disabled

# Windows Push Notifications System Service
#Stop-Service WpnService
#Set-Service WpnService -StartupType Disabled

# CDPUserSvc 
$serviceCDPUSer = Write-Output "CDPUserSvc_$suffix"
Stop-Service $serviceCDPUSer

#Stop-Service CDPUserSvc*
#Set-Service CDPUserSvc* -StartupType Disabled

# Connected Devices Platform Service 
Stop-Service CDPSvc
Set-Service CDPSvc -StartupType Disabled

# Adobe Acrobat Update Service
Stop-Service AdobeARMservice
Set-Service AdobeARMservice -StartupType Disabled

# Xbox Live Game Save
Stop-Service XblGameSave
Set-Service XblGameSave -StartupType Disabled

# Xbox Live Auth Manager
Stop-Service XblAuthManager
Set-Service XblAuthManager -StartupType Disabled

# SSDP Discovery
Stop-Service SSDPSRV
Set-Service SSDPSRV -StartupType Disabled

# Windows Audio
#Stop-Service Audiosrv
#Set-Service Audiosrv -StartupType Disabled

# Windows Audio Endpoint Builder
#Stop-Service AudioEndpointBuilder
#Set-Service AudioEndpointBuilder -StartupType Disabled

# Certificate Propagation
Stop-Service CertPropSvc
Set-Service CertPropSvc -StartupType Disabled

# Geolocation Service
Stop-Service lfsvc
Set-Service lfsvc -StartupType Disabled

# Network Connection Broker
Stop-Service NcbService
Set-Service NcbService -StartupType Disabled

#-------------------------------------------------------------------------------------------------

# Windows Update Service
Stop-Service wuauserv
Set-Service NcbService -StartupType Manual
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU -Name NoAutoUpdate -Value 1 -PropertyType "DWord"
