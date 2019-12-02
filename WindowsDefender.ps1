# . "C:\Scripts\BuildImageScripts\92.WindowsDefender.ps1"
#Requires -RunAsAdministrator 

<#
To enable Windows Defender manually

If Windows Defender is not enabled on your base image, you can enable it manually. To do so, complete the following steps.

Open the AppStream 2.0 console at https://console.aws.amazon.com/appstream2.

In the left navigation pane, choose Images, Image Builder.

Choose the image builder on which to enable Windows Defender, verify that it is in the Running state, and choose Connect.

Log in to the image builder with the local Administrator account or with a domain user account that has local administrator permissions.

Open Registry Editor.

Navigate to the following location in the registry: HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware.

To edit this registry key, double-click it, or right-click the registry key, and choose Modify.

In the Edit DWORD (32-bit) Value dialog box, in Value data, change 1 to 0.

Choose OK.

Close Registry Editor.

Open the Microsoft Management Console (MMC) Services snap-in (services.msc).

In the list of services, do either of the following:

Right-click Windows Defender Antivirus Service, and choose Start.

Double-click Windows Defender Antivirus Service, choose Start in the properties dialog box, and then choose OK.

Close the Services snap-in.
<##>

<#
Hi guys,

The antimalware for the AppStream session is not only for FSx scan, but for avoiding malicious file execution in the AppStream session.
I would suggest to apply a fine-tuning configuration using the Windows Defender Local Policies like:
-	Whitelisting on “Process Exclusions” every .EXE and .DLL from HSO (do not use *.dll neither *.exe, please)
o	E.g.: Z:\ExeFolder\App.exe
-	Whitelisting the DB file (here you can use *.DAT or the extension of DB)
-	Disable the folder scans – we need only the real-time scanning

After that, test it to see if the things work better.
Ands let me know to test the protections again.


<##>
<#
Set-MpPreference
   [-ExclusionPath <String[]>]
   [-ExclusionExtension <String[]>]
   [-ExclusionProcess <String[]>]
   [-RealTimeScanDirection <ScanDirection>]
   [-QuarantinePurgeItemsAfterDelay <UInt32>]
   [-RemediationScheduleDay <Day>]
   [-RemediationScheduleTime <DateTime>]
   [-ReportingAdditionalActionTimeOut <UInt32>]
   [-ReportingCriticalFailureTimeOut <UInt32>]
   [-ReportingNonCriticalTimeOut <UInt32>]
   [-ScanAvgCPULoadFactor <Byte>]
   [-CheckForSignaturesBeforeRunningScan <Boolean>]
   [-ScanPurgeItemsAfterDelay <UInt32>]
   [-ScanOnlyIfIdleEnabled <Boolean>]
   [-ScanParameters <ScanType>]
   [-ScanScheduleDay <Day>]
   [-ScanScheduleQuickScanTime <DateTime>]
   [-ScanScheduleTime <DateTime>]
   [-SignatureFirstAuGracePeriod <UInt32>]
   [-SignatureAuGracePeriod <UInt32>]
   [-SignatureDefinitionUpdateFileSharesSources <String>]
   [-SignatureDisableUpdateOnStartupWithoutEngine <Boolean>]
   [-SignatureFallbackOrder <String>]
   [-SignatureScheduleDay <Day>]
   [-SignatureScheduleTime <DateTime>]
   [-SignatureUpdateCatchupInterval <UInt32>]
   [-SignatureUpdateInterval <UInt32>]
   [-MAPSReporting <MAPSReportingType>]
   [-SubmitSamplesConsent <SubmitSamplesConsentType>]
   [-DisableAutoExclusions <Boolean>]
   [-DisablePrivacyMode <Boolean>]
   [-RandomizeScheduleTaskTimes <Boolean>]
   [-DisableBehaviorMonitoring <Boolean>]
   [-DisableIntrusionPreventionSystem <Boolean>]
   [-DisableIOAVProtection <Boolean>]
   [-DisableRealtimeMonitoring <Boolean>]
   [-DisableScriptScanning <Boolean>]
   [-DisableArchiveScanning <Boolean>]
   [-DisableCatchupFullScan <Boolean>]
   [-DisableCatchupQuickScan <Boolean>]
   [-DisableEmailScanning <Boolean>]
   [-DisableRemovableDriveScanning <Boolean>]
   [-DisableRestorePoint <Boolean>]
   [-DisableScanningMappedNetworkDrivesForFullScan <Boolean>]
   [-DisableScanningNetworkFiles <Boolean>]
   [-UILockdown <Boolean>]
   [-ThreatIDDefaultAction_Ids <Int64[]>]
   [-ThreatIDDefaultAction_Actions <ThreatAction[]>]
   [-UnknownThreatDefaultAction <ThreatAction>]
   [-LowThreatDefaultAction <ThreatAction>]
   [-ModerateThreatDefaultAction <ThreatAction>]
   [-HighThreatDefaultAction <ThreatAction>]
   [-SevereThreatDefaultAction <ThreatAction>]
   [-Force]
   [-DisableBlockAtFirstSeen <Boolean>]
   [-PUAProtection <PUAProtectionType>]
   [-CimSession <CimSession[]>]
   [-ThrottleLimit <Int32>]
   [-AsJob]
   [<CommonParameters>]
<##>
#$Preferences = Get-MpPreference
#$Preferences|ConvertTo-Json|Set-Content -Path 'C:\Scripts\logs\MpPreference.02.json'

#compare-object (get-content 'C:\Scripts\logs\MpPreference.01.json') (get-content 'C:\Scripts\logs\MpPreference.02.json')


#Set-MpPreference -DisableRealtimeMonitoring $false
#Set-MpPreference -ScanAvgCPULoadFactor 95
#Update-MpSignature

#& "C:\Program Files\Windows Defender\MpCmdRun.exe" -scan -scantype 2 -trace
#gc 'C:\Users\IMAGEB~1\AppData\Local\Temp\MpCmdRun.log'


<#
CheckForSignaturesBeforeRunningScan           : False
ComputerID                                    : 2B8184E4-CB70-45F4-919A-5F7B2783D587
DisableArchiveScanning                        : False
DisableAutoExclusions                         : False
DisableBehaviorMonitoring                     : False
DisableBlockAtFirstSeen                       : False
DisableCatchupFullScan                        : True
DisableCatchupQuickScan                       : True
DisableEmailScanning                          : True
DisableIntrusionPreventionSystem              : 
DisableIOAVProtection                         : False
DisablePrivacyMode                            : False
DisableRealtimeMonitoring                     : False
DisableRemovableDriveScanning                 : True
DisableRestorePoint                           : True
DisableScanningMappedNetworkDrivesForFullScan : True
DisableScanningNetworkFiles                   : False
DisableScriptScanning                         : False
ExclusionExtension                            : 
ExclusionPath                                 : {C:\Scripts}
ExclusionProcess                              : 
HighThreatDefaultAction                       : 0
LowThreatDefaultAction                        : 0
MAPSReporting                                 : 0
ModerateThreatDefaultAction                   : 0
PUAProtection                                 : 0
QuarantinePurgeItemsAfterDelay                : 90
RandomizeScheduleTaskTimes                    : True
RealTimeScanDirection                         : 0
RemediationScheduleDay                        : 0
RemediationScheduleTime                       : 02:00:00
ReportingAdditionalActionTimeOut              : 10080
ReportingCriticalFailureTimeOut               : 10080
ReportingNonCriticalTimeOut                   : 1440
ScanAvgCPULoadFactor                          : 5
ScanOnlyIfIdleEnabled                         : True
ScanParameters                                : 1
ScanPurgeItemsAfterDelay                      : 15
ScanScheduleDay                               : 0
ScanScheduleQuickScanTime                     : 00:00:00
ScanScheduleTime                              : 02:00:00
SevereThreatDefaultAction                     : 0
SignatureAuGracePeriod                        : 1440
SignatureDefinitionUpdateFileSharesSources    : 
SignatureDisableUpdateOnStartupWithoutEngine  : False
SignatureFallbackOrder                        : MicrosoftUpdateServer|MMPC
SignatureFirstAuGracePeriod                   : 120
SignatureScheduleDay                          : 8
SignatureScheduleTime                         : 01:45:00
SignatureUpdateCatchupInterval                : 1
SignatureUpdateInterval                       : 0
SubmitSamplesConsent                          : 0
ThreatIDDefaultAction_Actions                 : 
ThreatIDDefaultAction_Ids                     : 
UILockdown                                    : False
UnknownThreatDefaultAction                    : 0
PSComputerName                                : 

<##>

# [io.file]::WriteAllText("test.txt",'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

<##>
Set-MpPreference -DisableRealtimeMonitoring $false
Set-MpPreference -ScanAvgCPULoadFactor 50
Set-MpPreference -DisableIntrusionPreventionSystem $false
Set-MpPreference -DisableScanningNetworkFiles $true
Set-MpPreference -ExclusionExtension @('.ind','.dat')
Set-MpPreference -ExclusionPath      @('C:\','C:\*.*','C:\*')
Set-MpPreference -ExclusionProcess   @('Z:\Apps\Ha19.exe','Z:\Apps\Hl19.exe','Z:\Apps\Hs.exe','Z:\Apps\Hct19.exe','Z:\Apps\Hr19.exe','Z:\Apps\Hsf19.exe','Z:\Apps\Ht19.exe','Z:\Apps\Hm19.exe','Z:\Apps\Hta19.exe','Z:\Apps\Ha19Sql.exe','Z:\Apps\Hl19Sql.exe','Z:\Apps\HsSQL.exe','Z:\Apps\Hct19Sql.exe','Z:\Apps\Hr19Sql.exe','Z:\Apps\Hsf19Sql.exe','Z:\Apps\Ht19SQL.exe','Z:\Apps\Hm19Sql.exe','Z:\Apps\Hta19Sql.exe','Z:\Apps\H*.exe','Ha19.exe','Hl19.exe','Hs.exe','Hct19.exe','Hr19.exe','Hsf19.exe','Ht19.exe','Hm19.exe','Hta19.exe','Ha19Sql.exe','Hl19Sql.exe','HsSQL.exe','Hct19Sql.exe','Hr19Sql.exe','Hsf19Sql.exe','Ht19SQL.exe','Hm19Sql.exe','Hta19Sql.exe','Ha??.exe''Hl??.exe','Hct??.exe','Hr??.exe','Hsf??.exe','Ht??.exe','Hm??.exe','Hta??.exe','Ha??Sql.exe','Hl??Sql.exe','Hct??Sql.exe','Hr??Sql.exe','Hsf??Sql.exe','Ht??SQL.exe','Hm??Sql.exe','Hta??Sql.exe')

Disable-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName 'Windows Defender Scheduled Scan'

<##>
(Get-WmiObject -class Win32_OperatingSystem).Caption
Get-MpComputerStatus
Get-MpPreference
Get-ScheduledTask -TaskPath "\Microsoft\Windows\Windows Defender\" -TaskName 'Windows Defender Scheduled Scan'|Select-Object -Property TaskName,State

<#PS C:\Windows\system32> C:\Scripts\BuildImageScripts\92.WindowsDefender.ps1

TaskPath                                       TaskName                          State     
--------                                       --------                          -----     
\Microsoft\Windows\Windows Defender\           Windows Defender Scheduled Scan   Disabled  

AMEngineVersion                 : 1.1.16500.1
AMProductVersion                : 4.18.1905.4
AMServiceEnabled                : True
AMServiceVersion                : 4.18.1905.4
AntispywareEnabled              : True
AntispywareSignatureAge         : 0
AntispywareSignatureLastUpdated : 11/21/2019 6:54:41 PM
AntispywareSignatureVersion     : 1.305.2574.0
AntivirusEnabled                : True
AntivirusSignatureAge           : 0
AntivirusSignatureLastUpdated   : 11/21/2019 6:54:43 PM
AntivirusSignatureVersion       : 1.305.2574.0
BehaviorMonitorEnabled          : True
ComputerID                      : A0AF1118-E362-4D18-B870-357C567C7142
ComputerState                   : 0
FullScanAge                     : 4294967295
FullScanEndTime                 : 
FullScanStartTime               : 
IoavProtectionEnabled           : True
LastFullScanSource              : 0
LastQuickScanSource             : 2
NISEnabled                      : True
NISEngineVersion                : 1.1.16500.1
NISSignatureAge                 : 0
NISSignatureLastUpdated         : 11/21/2019 6:54:43 PM
NISSignatureVersion             : 1.305.2574.0
OnAccessProtectionEnabled       : True
QuickScanAge                    : 0
QuickScanEndTime                : 11/21/2019 2:07:14 AM
QuickScanStartTime              : 11/21/2019 2:03:48 AM
RealTimeProtectionEnabled       : True
RealTimeScanDirection           : 0
PSComputerName                  : 


AttackSurfaceReductionOnlyExclusions          : 
AttackSurfaceReductionRules_Actions           : 
AttackSurfaceReductionRules_Ids               : 
CheckForSignaturesBeforeRunningScan           : False
CloudBlockLevel                               : 0
CloudExtendedTimeout                          : 0
ComputerID                                    : A0AF1118-E362-4D18-B870-357C567C7142
ControlledFolderAccessAllowedApplications     : 
ControlledFolderAccessProtectedFolders        : 
DisableArchiveScanning                        : False
DisableAutoExclusions                         : False
DisableBehaviorMonitoring                     : False
DisableBlockAtFirstSeen                       : False
DisableCatchupFullScan                        : True
DisableCatchupQuickScan                       : True
DisableEmailScanning                          : True
DisableIntrusionPreventionSystem              : 
DisableIOAVProtection                         : False
DisablePrivacyMode                            : False
DisableRealtimeMonitoring                     : False
DisableRemovableDriveScanning                 : True
DisableRestorePoint                           : True
DisableScanningMappedNetworkDrivesForFullScan : True
DisableScanningNetworkFiles                   : True
DisableScriptScanning                         : False
EnableControlledFolderAccess                  : 0
EnableLowCpuPriority                          : False
EnableNetworkProtection                       : 0
ExclusionExtension                            : {.dat, .ind}
ExclusionPath                                 : {C:\}
ExclusionProcess                              : {Z:\Apps\Ha19.exe, Z:\Apps\Ha19Sql.exe, Z:\Apps\Hct19.exe, Z:\Apps\Hct19Sql.exe...}
HighThreatDefaultAction                       : 0
LowThreatDefaultAction                        : 0
MAPSReporting                                 : 2
ModerateThreatDefaultAction                   : 0
PUAProtection                                 : 0
QuarantinePurgeItemsAfterDelay                : 90
RandomizeScheduleTaskTimes                    : True
RealTimeScanDirection                         : 0
RemediationScheduleDay                        : 0
RemediationScheduleTime                       : 02:00:00
ReportingAdditionalActionTimeOut              : 10080
ReportingCriticalFailureTimeOut               : 10080
ReportingNonCriticalTimeOut                   : 1440
ScanAvgCPULoadFactor                          : 50
ScanOnlyIfIdleEnabled                         : True
ScanParameters                                : 1
ScanPurgeItemsAfterDelay                      : 15
ScanScheduleDay                               : 0
ScanScheduleQuickScanTime                     : 00:00:00
ScanScheduleTime                              : 02:00:00
SevereThreatDefaultAction                     : 0
SignatureAuGracePeriod                        : 0
SignatureDefinitionUpdateFileSharesSources    : 
SignatureDisableUpdateOnStartupWithoutEngine  : False
SignatureFallbackOrder                        : MicrosoftUpdateServer|MMPC
SignatureFirstAuGracePeriod                   : 120
SignatureScheduleDay                          : 8
SignatureScheduleTime                         : 01:45:00
SignatureUpdateCatchupInterval                : 1
SignatureUpdateInterval                       : 0
SubmitSamplesConsent                          : 1
ThreatIDDefaultAction_Actions                 : 
ThreatIDDefaultAction_Ids                     : 
UILockdown                                    : False
UnknownThreatDefaultAction                    : 0
PSComputerName                                : 


TaskName : Windows Defender Scheduled Scan
State    : Disabled

<##>
