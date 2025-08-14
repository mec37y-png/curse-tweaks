# revert.ps1 — Full deactivate/rollback for Bloom Pack (covers entire tweak.txt)
# Run as Administrator. Optional: -DryRun

[CmdletBinding()]
param([switch]$DryRun)

$ErrorActionPreference = 'Stop'
$LogDir = "$env:ProgramData\Curse\Revert"
$Log    = Join-Path $LogDir "revert.log"
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

function Write-Log { param([string]$m) "$([DateTime]::Now.ToString('yyyy-MM-dd HH:mm:ss')) $m" | Tee-Object -FilePath $Log -Append }
function Do { param([scriptblock]$b,[string]$d) if($DryRun){Write-Log "[DRY] $d"} else {Write-Log "[RUN] $d"; & $b} }
function IsAdmin { $p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }
if(-not (IsAdmin)) { Write-Error "Start PowerShell as Administrator."; exit 1 }

# ---------- Restore point ----------
try { Do { Checkpoint-Computer -Description "Curse Revert Point" -ErrorAction Stop } "Create System Restore Point" } catch { Write-Log "Restore point skipped: $($_.Exception.Message)" }

# ---------- Helpers ----------
function Remove-Value { param([string]$Hive,[string]$Path,[string]$Name)
  $full="Registry::$Hive\$Path"
  if(Test-Path $full){
    $has=(Get-ItemProperty -Path $full -ErrorAction SilentlyContinue).PSObject.Properties.Name -contains $Name
    if($has){ Do { Remove-ItemProperty -Path $full -Name $Name -Force } "REG DEL: $Hive\$Path -> $Name" } else { Write-Log "SKIP (not set): $Hive\$Path -> $Name" }
  } else { Write-Log "SKIP (path missing): $Hive\$Path" }
}
function Set-DWord { param([string]$Hive,[string]$Path,[string]$Name,[int]$Value)
  $full="Registry::$Hive\$Path"; if(-not (Test-Path $full)){ Do { New-Item -Path $full -Force | Out-Null } "Create $Hive\$Path" }
  $cur=(Get-ItemProperty -Path $full -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
  if($cur -ne $Value){ Do { New-ItemProperty -Path $full -Name $Name -Value $Value -PropertyType DWord -Force | Out-Null } "REG SET: $Hive\$Path -> $Name=$Value" } else { Write-Log "OK (already $Value): $Hive\$Path -> $Name" }
}
function Set-Str { param([string]$Hive,[string]$Path,[string]$Name,[string]$Value,[string]$Type="String")
  $full="Registry::$Hive\$Path"; if(-not (Test-Path $full)){ Do { New-Item -Path $full -Force | Out-Null } "Create $Hive\$Path" }
  $cur=(Get-ItemProperty -Path $full -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $Name -ErrorAction SilentlyContinue)
  if($cur -ne $Value){ Do { New-ItemProperty -Path $full -Name $Name -Value $Value -PropertyType $Type -Force | Out-Null } "REG SET: $Hive\$Path -> $Name=$Value" } else { Write-Log "OK (already $Value): $Hive\$Path -> $Name" }
}
function Ensure-Key { param([string]$Hive,[string]$Path) $full="Registry::$Hive\$Path"; if(-not (Test-Path $full)){ Do { New-Item -Path $full -Force | Out-Null } "Create $Hive\$Path" } else { Write-Log "OK (key exists): $Hive\$Path" } }
function Remove-Key { param([string]$Hive,[string]$Path) $full="Registry::$Hive\$Path"; if(Test-Path $full){ Do { Remove-Item -Path $full -Recurse -Force } "REG DELETE KEY: $Hive\$Path" } else { Write-Log "SKIP (key not present): $Hive\$Path" } }

# ---------- Close Settings ----------
Do { Stop-Process -Name "SystemSettings" -Force -ErrorAction SilentlyContinue } "Close Settings app"

# ---------- Windows Update / SoftwareDistribution ----------
foreach($t in @(
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate","DoNotConnectToWindowsUpdateInternetLocations"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate","SetDisableUXWUAccess"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","NoAutoUpdate"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU","AUOptions"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate","ExcludeWUDriversInQualityUpdate"),
  @("HKLM","SOFTWARE\Microsoft\WindowsUpdate\UX\Settings","ExcludeWUDriversInQualityUpdate"),
  @("HKLM","SOFTWARE\Microsoft\PolicyManager\current\device\Update","ExcludeWUDriversInQualityUpdate"),
  @("HKLM","SOFTWARE\Microsoft\PolicyManager\default\Update","ExcludeWUDriversInQualityUpdate"),
  @("HKLM","SOFTWARE\Microsoft\PolicyManager\default\Update\ExcludeWUDriversInQualityUpdate","value")
)){ Remove-Value @t }
if(-not (Test-Path "C:\Windows\SoftwareDistribution")){ Do { New-Item "C:\Windows\SoftwareDistribution" -ItemType Directory -Force | Out-Null } "Restore SoftwareDistribution" }
foreach($svc in "wuauserv","UsoSvc"){ Do { Start-Service -Name $svc -ErrorAction SilentlyContinue } "Start service: $svc" }

# ---------- System Restore defaults ----------
Ensure-Key "HKLM" "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore"
foreach($n in "RPSessionInterval","DisableConfig","SystemRestorePointCreationFrequency"){ Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" $n }

# ---------- UAC / Power / Memory ----------
Set-DWord "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" 1
Set-DWord "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" 1
Set-DWord "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" 5
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableAutomaticRestartSignOn"
Do { powercfg -h on } "Enable hibernation"
Set-DWord "HKLM" "SYSTEM\CurrentControlSet\Control\Session Manager\Power" "HiberbootEnabled" 1
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Power" "HibernateEnabled"
Do { powercfg -setacvalueindex scheme_current SUB_PROCESSOR IDLEDISABLE 0 } "CPU idle states (AC) enabled"
Do { powercfg -setdcvalueindex scheme_current SUB_PROCESSOR IDLEDISABLE 0 } "CPU idle states (DC) enabled"
Do { powercfg -setactive 381b4222-f694-41f0-9685-ff5bb260df2e } "Activate Balanced power plan"
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" "PowerThrottlingOff"
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverride"
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "FeatureSettingsOverrideMask"
Set-DWord "HKLM" "SYSTEM\CurrentControlSet\Control\PriorityControl" "Win32PrioritySeparation" 26
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" "DisablePagingExecutive"
Set-DWord "HKLM" "SYSTEM\ControlSet001\Control\Session Manager\Memory Management\PrefetchParameters" "EnablePrefetcher" 3

# ---------- BCDEdit ----------
Do { & bcdedit /deletevalue useplatformtick } "BCDEdit: remove useplatformtick"
Do { & bcdedit /deletevalue disabledynamictick } "BCDEdit: remove disabledynamictick"

# ---------- Device metadata / driver search ----------
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" "PreventDeviceMetadataFromNetwork"
Set-DWord   "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" "SearchOrderConfig" 1

# ---------- Multimedia / Scheduler ----------
Set-DWord "HKLM" "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "NetworkThrottlingIndex" 10
Set-DWord "HKLM" "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" "SystemResponsiveness" 20
$gamesPath="SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
foreach($n in "Affinity","GPU Priority","Priority","Clock Rate","Scheduling Category","Background Only","SFIO Priority"){ Remove-Value "HKLM" $gamesPath $n }

# ---------- Explorer / Start / UI ----------
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoUseStoreOpenWith"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoNewAppAlert"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "HideRecentlyAddedApps"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideRecentlyAddedApps"
Remove-Value "HKCU" "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoStartMenuMorePrograms"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoStartMenuMorePrograms"
Remove-Value "HKCU" "SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter"
Remove-Value "HKCU" "SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoTileApplicationNotification"
Remove-Value "HKCU" "Software\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Shell\ActionCenter\Quick Actions" "PinnedQuickActionSlotCount"
Set-DWord   "HKCU" "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Start_TrackDocs" 1
Set-DWord   "HKCU" "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "TaskbarBadges" 1
Remove-Value "HKCU" "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" "TaskbarCapacity"
Ensure-Key "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
Ensure-Key "HKLM" "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
Set-DWord   "HKCR" "CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 1
Set-DWord   "HKCR" "Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 1
Remove-Value "HKCR" "CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" "Attributes"
Remove-Value "HKCR" "WOW6432Node\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}\ShellFolder" "Attributes"
Remove-Value "HKCU" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" "link"
Remove-Value "HKCU" "Control Panel\Desktop" "JPEGImportQuality"
Set-Str    "HKCU" "Control Panel\Desktop" "MenuShowDelay" "400"
$cdm="SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach($n in "SilentInstalledAppsEnabled","SystemPaneSuggestionsEnabled","SoftLandingEnabled",
  "RotatingLockScreenEnabled","RotatingLockScreenOverlayEnabled",
  "SubscribedContent-310093Enabled","SubscribedContent-314563Enabled",
  "SubscribedContent-338387Enabled","SubscribedContent-338388Enabled",
  "SubscribedContent-338389Enabled","SubscribedContent-338393Enabled","SubscribedContent-353698Enabled"){
  Remove-Value "HKCU" $cdm $n
}
Remove-Value "HKCU" "Software\Microsoft\Windows\CurrentVersion\Themes" "ThemeChangesDesktopIcons"
Remove-Value "HKCU" "Software\Microsoft\Windows\CurrentVersion\Themes" "ThemeChangesMousePointers"
Set-DWord   "HKCU" "Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" "EnableTransparency" 1
foreach($pair in @(
  @("HKCU","Software\Microsoft\Windows\DWM","AccentColor"),
  @("HKCU","Software\Microsoft\Windows\DWM","ColorizationColor"),
  @("HKCU","Software\Microsoft\Windows\DWM","ColorizationAfterglow"),
  @("HKCU","Software\Microsoft\Windows\DWM","ColorizationGlassAttribute"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent","AccentColorMenu"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent","StartColorMenu"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent","AccentPalette")
)){ Remove-Value @pair }

# ---------- Privacy / Telemetry / Store / Edge / Defender / SmartScreen ----------
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\MRT" "DontOfferThroughWUAU"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "EnableActivityFeed"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "PublishUserActivities"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "UploadUserActivities"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "DisableLogonBackgroundImage"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "DisableAcrylicBackgroundOnLogon"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\System" "EnableSmartScreen"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\Windows Error Reporting" "Disabled"
foreach($t in @(
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection","DisableRealtimeMonitoring"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows Defender\Spynet","SubmitSamplesConsent"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows Defender\Spynet","SpynetReporting"),
  @("HKLM","SOFTWARE\Microsoft\Windows Defender\Features","TamperProtection"),
  @("HKLM","SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray","HideSystray"),
  @("HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run","SecurityHealth")
)){ Remove-Value @t }
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" "EnabledV9"
Remove-Value "HKLM" "SOFTWARE\Policies\Mozilla\Firefox" "DisableAppUpdate"
Remove-Value "HKCU" "Software\Microsoft\OneDrive\Accounts\Personal" "ShareNotificationDisabled"
Remove-Value "HKCU" "Software\Microsoft\OneDrive\Accounts\Personal" "MassDeleteNotificationDisabled"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\Windows Search" "AllowCloudSearch"
foreach($t in @(
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Search","DeviceHistoryEnabled"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Search","BingSearchEnabled"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Search","AllowSearchToUseLocation"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Search","CortanaConsent"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings","SafeSearchMode"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings","IsDeviceSearchHistoryEnabled")
)){ Remove-Value @t }
foreach($p in @(
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings","NOC_GLOBAL_SETTING_ALLOW_NOTIFICATION_SOUND"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings","NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings","NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel","Enabled"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications","ToastEnabled"),
  @("HKCU","SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications","LockScreenToastEnabled"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\Bluetooth","QuickPair"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\PushNotifications","DatabaseMigrationCompleted")
)){ Remove-Value @p }
Remove-Key  "HKCU" "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"
Remove-Key  "HKCU" "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" "Value"
Remove-Value "HKLM" "SOFTWARE\Microsoft\WindowsMitigation" "UserPreference"
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowFullControl"
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp"
Remove-Value "HKCU" "SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" "AgentActivationEnabled"
Remove-Value "HKCU" "SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" "AgentActivationLastUsed"
Remove-Value "HKCU" "SOFTWARE\Microsoft\Siuf\Rules" "NumberOfSIUFInPeriod"
Remove-Value "HKCU" "SOFTWARE\Microsoft\Siuf\Rules" "PeriodInNanoSeconds"

# ---------- GameDVR / Game Bar ----------
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR"
Set-DWord   "HKCU" "SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" "AppCaptureEnabled" 1
foreach($n in "GameDVR_Enabled","GameDVR_FSEBehaviorMode","GameDVR_FSEBehavior","GameDVR_HonorUserFSEBehaviorMode","GameDVR_DXGIHonorFSEWindowsCompatible","GameDVR_EFSEFeatureFlags","GameDVR_DSEBehavior"){
  Remove-Value "HKCU" "System\GameConfigStore" $n
}
Set-DWord "HKCU" "Software\Microsoft\GameBar" "UseNexusForGameBarEnabled" 1
Remove-Value "HKCU" "Software\Microsoft\GameBar" "ShowStartupPanel"
Remove-Value "HKCU" "Software\Microsoft\GameBar" "GamePanelStartupTipIndex"
Set-DWord "HKCU" "Software\Microsoft\GameBar" "AllowAutoGameMode" 1
Set-DWord "HKCU" "Software\Microsoft\GameBar" "AutoGameModeEnabled" 1

# ---------- Mouse / Input ----------
Set-Str  "HKCU" "Control Panel\Mouse" "MouseSpeed" "1"
Set-Str  "HKCU" "Control Panel\Mouse" "MouseThreshold1" "6"
Set-Str  "HKCU" "Control Panel\Mouse" "MouseThreshold2" "10"
Remove-Value "HKCU" "Control Panel\Mouse" "MouseSensitivity"
foreach($n in "MouseHoverTime","MouseSpeed","MouseThreshold1","MouseThreshold2"){ Remove-Value "HKU" ".DEFAULT\Control Panel\Mouse" $n }
$cursorPath="Control Panel\Cursors"
foreach($n in "AppStarting","Arrow","ContactVisualization","Crosshair","GestureVisualization","Hand","Help","IBeam","No","NWPen","Scheme Source","SizeAll","SizeNESW","SizeNS","SizeNWSE","SizeWE","UpArrow","Wait"){ Remove-Value "HKCU" $cursorPath $n }
Remove-Value "HKCU" $cursorPath ""
foreach($n in "Language Hotkey","Hotkey","Layout Hotkey"){ Remove-Value "HKCU" "Keyboard Layout\Toggle" $n }
foreach($kv in @(
  @("HKCU","Software\Microsoft\CTF\LangBar","ShowStatus"),
  @("HKCU","Software\Microsoft\CTF\LangBar","ExtraIconsOnMinimized"),
  @("HKCU","Software\Microsoft\CTF\LangBar","Transparency"),
  @("HKCU","Software\Microsoft\CTF\LangBar","Label"),
  @("HKCU","Control Panel\Accessibility\MouseKeys","Flags"),
  @("HKCU","Control Panel\Accessibility\MouseKeys","MaximumSpeed"),
  @("HKCU","Control Panel\Accessibility\MouseKeys","TimeToMaximumSpeed"),
  @("HKCU","Control Panel\Accessibility\HighContrast","Flags"),
  @("HKCU","Control Panel\Accessibility\SoundSentry","Flags"),
  @("HKCU","Control Panel\Accessibility\SoundSentry","FSTextEffect"),
  @("HKCU","Control Panel\Accessibility\SoundSentry","TextEffect"),
  @("HKCU","Control Panel\Accessibility\SoundSentry","WindowsEffect"),
  @("HKCU","Control Panel\Accessibility\SlateLaunch","ATapp"),
  @("HKCU","Control Panel\Accessibility\SlateLaunch","LaunchAT"),
  @("HKCU","Control Panel\Accessibility\StickyKeys","Flags"),
  @("HKCU","Control Panel\Accessibility\Keyboard Response","Flags"),
  @("HKCU","Control Panel\Accessibility","Sound on Activation"),
  @("HKCU","Control Panel\Accessibility","Warning Sounds")
)){ Remove-Value @kv }
foreach($kv in @(
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\ImmersiveShell","TabletMode"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\ImmersiveShell","SignInMode"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\ImmersiveShell","ConvertibleSlateModePromptPreference"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","TaskbarAppsVisibleInTabletMode"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","TaskbarAutoHideInTabletMode"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","VirtualDesktopTaskbarFilter"),
  @("HKCU","Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced","VirtualDesktopAltTabFilter")
)){ Remove-Value @kv }
foreach($n in "EnableTextPrediction","EnablePredictionSpaceInsertion","EnableDoubleTapSpace"){ Remove-Value "HKCU" "Software\Microsoft\TabletTip\1.7" $n }

# ---------- Time service ----------
Set-Str "HKLM" "SYSTEM\CurrentControlSet\Services\W32Time\Parameters" "Type" "NTP"
Do { Restart-Service W32Time -ErrorAction SilentlyContinue } "Restart W32Time"

# ---------- Power flyout / printers / scroll / audio ----------
foreach($n in "ShowSleepOption","ShowLockOption"){ Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" $n }
Remove-Value "HKCU" "Software\Microsoft\Windows NT\CurrentVersion\Windows" "LegacyDefaultPrinterMode"
Remove-Value "HKCU" "Control Panel\Desktop" "MouseWheelRouting"
Remove-Value "HKCU" "Software\Microsoft\Multimedia\Audio" "UserDuckingPreference"
foreach($n in "NotifyOnUsbErrors","NotifyOnWeakCharger"){ Remove-Value "HKCU" "SOFTWARE\Microsoft\Shell\USB" $n }
Remove-Value "HKLM" "SYSTEM\Maps" "AutoUpdateEnabled"

# ---------- Networking registry ----------
foreach($v in @(
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","DelayedAckFrequency"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","DelayedAckTicks"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","CongestionAlgorithm"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","MultihopSets"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","FastCopyReceiveThreshold"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\Parameters","FastSendDatagramThreshold"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider","LocalPriority"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider","HostsPriority"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider","DnsPriority"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider","NetbtPriority"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","DefaultReceiveWindow"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","DefaultSendWindow"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","FastCopyReceiveThreshold"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","FastSendDatagramThreshold"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","DynamicSendBufferDisable"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","IgnorePushBitOnReceives"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","NonBlockingSendSpecialBuffering"),
  @("HKLM","SYSTEM\CurrentControlSet\Services\AFD\Parameters","DisableRawSecurity")
)){ Remove-Value @v }

# ---------- Netsh / TCP/IP / IPv6 / interfaces ----------
# Explicitly revert all globals that were modified in tweak.txt
Do { & netsh int ip set global dhcpmediasense=enabled } "IP: DHCP Media Sense enabled"
Do { & netsh int ip set global loopbacklargemtu=enabled } "IP: Loopback Large MTU enabled"
Do { & netsh int ip set global mediasenseeventlog=enabled } "IP: Media Sense event log enabled"
Do { & netsh int ip set global mldlevel=all } "IP: MLD level all"
Do { & netsh int ip set global multicastforwarding=disabled } "IP: Multicast forwarding disabled (default)"
Do { & netsh int ip set global neighborcachelimit=default } "IP: Neighbor cache limit default"
Do { & netsh int ip set global routecachelimit=default } "IP: Route cache limit default"
Do { & netsh int ip set global sourceroutingbehavior=dontdrop } "IP: Source routing not forced to drop"
Do { & netsh int ip set global taskoffload=enabled } "IP: Task offload enabled"
Do { & netsh int ip set global icmpredirects=enabled } "IP: ICMP redirects enabled"
Do { & netsh int ipv4 set dynamicport tcp start=49152 num=16384 } "IPv4 TCP dynamic ports default"
Do { & netsh int ipv4 set dynamicport udp start=49152 num=16384 } "IPv4 UDP dynamic ports default"
Do { & netsh interface ipv6 set state enabled } "IPv6: enabled"
Do { & netsh interface 6to4 set state default } "6to4: default"
Do { & netsh interface isatap set state default } "ISATAP: default"
Do { & netsh interface teredo set state default } "Teredo: default"

# TCP features back to defaults
Do { & netsh int tcp set heuristics enabled } "TCP heuristics enabled"
Do { & netsh int tcp set global autotuninglevel=normal } "TCP autotuning normal"
Do { & netsh int tcp set global ecncapability=default } "TCP ECN default"
Do { & netsh int tcp set global timestamps=default } "TCP timestamps default"
Do { & netsh int tcp set global rss=enabled } "TCP RSS enabled"
Do { & netsh int tcp set global rsc=enabled } "TCP RSC enabled"
Do { & netsh int tcp set global chimney=default } "TCP Chimney default"
Do { & netsh int tcp set supplemental internet congestionprovider=default } "TCP congestion provider default"
Do { & netsh int tcp set global nonsackrttresiliency=enabled } "TCP nonSACK RTT resiliency enabled"
Do { & netsh int tcp set global dca=default } "TCP DCA default"
Do { & netsh int tcp set global netdma=default } "TCP NetDMA default"
Do { & netsh int tcp set global hystart=default } "TCP HyStart default"

# Full stack resets (covers interface-scoped changes)
Do { & netsh int ip reset } "Reset IPv4 stack"
Do { & netsh int ipv6 reset } "Reset IPv6 stack"
Do { & netsh winsock reset } "Winsock reset"

# ---------- NIC features ----------
Do { Get-NetAdapter -Physical | ForEach-Object { Enable-NetAdapterLso -Name $_.Name -ErrorAction SilentlyContinue } } "Enable LSO on physical adapters"

# ---------- Firewall ----------
Do { & netsh advfirewall reset } "Windows Firewall policy reset"

# ---------- Graphics ----------
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Control\GraphicsDrivers" "HwSchMode"

# ---------- Apps for websites overrides ----------
Remove-Key "HKCU" "SOFTWARE\Microsoft\Windows\Shell\Associations\AppUrlAssociations\*.maps.windows.com\AppXw2ahfj46c0qbns74sb1bad9a5cpw8042\UserChoice"
Remove-Key "HKCU" "SOFTWARE\Microsoft\Windows\Shell\Associations\AppUrlAssociations\maps.windows.com\AppXpmv5ep1jbsan9pzb5ys5a2x5244nckxh\UserChoice"

# ---------- Admin shares / Store / Maintenance ----------
Remove-Value "HKLM" "SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
Remove-Value "HKLM" "SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload"
Remove-Value "HKLM" "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" "MaintenanceDisabled"

# ---------- Group Policy refresh ----------
Do { & gpupdate /force } "Group Policy update"

Write-Log "Rollback completed. Reboot recommended."
if($DryRun){ "DRY RUN complete. See: $Log" } else { "Revert complete. Details: $Log`nReboot recommended." }