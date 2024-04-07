@echo off
@setlocal
Color 0f
chcp 65001 > nul
SetLocal EnableExtensions EnableDelayedExpansion
pushd "%CD%" & CD /D "%~dp0" >nul
reg query "HKU\S-1-5-19" >nul 2>&1
if "%Errorlevel%" NEQ "0" "Work\nircmd.exe" elevate "%~f0" & exit
>nul reg add hkcu\software\classes\.Admin\shell\runas\command /f /ve /d "cmd /x /d /r set \"f0=%%2\"& call \"%%2\" %%3"& set _= %*
>nul fltmc|| if "%f0%" neq "%~f0" (cd.>"%temp%\runas.Admin" & start "%~n0" /high "%temp%\runas.Admin" "%~f0" "%_:"=""%" & exit /b)
fltmc >nul || (set Admin=/x /d /c call "%~f0" %* & powershell -nop -c start cmd $env:Admin -verb runas; & exit /b)
fltmc >nul 2>&1 || (
    echo Administrator privileges are required.
    PowerShell Start -Verb RunAs '%0' 2> nul || (
        echo Right-click on the script and select "Run as administrator".
        pause & exit 1
    )
exit 0
)
set start=%time%
set "ch=Work\cecho.exe"
set "NSudo=Work\NSudoLC.exe -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"
set "serviceswebmask="
for /f "usebackq delims=" %%n In (`2^>nul reg query "HKLM\%HIVE%\Services" /f "webthreatdefusersvc*" /k^|findstr ^H`) do set serviceswebmask=%%~nxn
if defined serviceswebmask (Mode 82,44) else (Mode 80,44)
"Work\nircmd.exe" win center process cmd.exe & "Work\nircmd.exe" win settext foreground "Null.Script.For.Windows.Telemetry"
:----------------------------------------------------------------------------:
:: Start
reg query "HKCU\Software\Null" /v "TelemetryStatus" >nul 2>&1 && echo already added >nul 2>&1 || REG Add "HKCU\Software\Null" /v "TelemetryStatus" /t REG_SZ /d "Enabled" /f >nul 2>&1
reg query HKCU\Software\Null /v TelemetryStatus | find "REG_SZ" | find "Enabled" >nul 2>&1
if "%ERRORLEVEL%"=="0" (
 ECHO.
 %ch% Current Windows Telemetry Status is: {0c}Enabled{\n #}
 ECHO.
 ECHO Disabling Windows Telemetry...
REM ; Disable Advertising ID and Advertising
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{E34EF00E-CAE7-4AD7-94E3-87843460B1F9}Machine\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f >nul 2>&1
REM ; Disable all types of Windows syncs
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mobsync.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\system32\systray.exe" /f >nul 2>&1
REM ; Disable all Windows and Visual Studio Telemetry
 REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\System\CurrentControlSet\Policies" /v "telemetry" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v "Debugger" /t REG_SZ /d "C:\Windows\system32\systray.exe" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "**del.AllowTelemetry" /t REG_SZ /d "" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "**del.CorporateSQMURL" /t REG_SZ /d "" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7709E9F0-5FED-4252-A59A-ABDEA285E693}Machine\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "**del.AllowTelemetry" /t REG_SZ /d "" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{F10E2328-DE4D-45CE-9E1B-7402EC26D5B4}Machine\SOFTWARE\Policies\Microsoft\SQMClient" /v "**del.CorporateSQMURL" /t REG_SZ /d "" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CD99AEF9-BC89-4010-AA54-B994270CEF34}Machine\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D23106FF-E46C-48D2-968F-87E724E31D90}Machine\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t REG_DWORD /d "1" /f >nul 2>&1
 schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /disable >nul 2>&1
 %NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" /V "Start" /T REG_DWORD /D "4" /f >nul 2>&1
 %NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "Start" /T REG_DWORD /D "4" /f >nul 2>&1
 %NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "Start" /T REG_DWORD /D "4" /f >nul 2>&1
REM ; Disable application usage statistics collection
 REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{6A0C3688-2712-48D3-AAB2-610B5DE06793}Machine\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A527F628-5DC1-474C-8E24-636BA8CF84E2}Machine\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >nul 2>&1
 schtasks /change /tn "\Microsoft\Windows\Management\Provisioning\Cellular" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Management\Provisioning\Logon" /disable >nul 2>&1
REM ; Disable collection and sending of ink data
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D700683C-175C-4062-A3BC-12AD216884B3}Machine\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A8BBE764-18C0-4D65-AB96-D3964729FD99}Machine\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CF7960B7-4399-4457-B22B-AD4708E96690}Machine\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CF7960B7-4399-4457-B22B-AD4708E96690}Machine\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >nul 2>&1
REM ; Disable collection of data about installed applications
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D1B49062-FF05-4294-B5E4-BE9BD0170C2C}Machine\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
REM ; Disable data collection via scheduler events
 schtasks /change /tn \Microsoft\Windows\Maintenance\WinSAT /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /disable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /disable >nul 2>&1
REM ; Disable Event Log data collection and processing
 REG Add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{E7C22CBD-D40F-47CA-A662-539B5E2CAD41}Machine\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{E7C22CBD-D40F-47CA-A662-539B5E2CAD41}Machine\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5AF81036-7117-4222-B135-8D3FF5FB15FC}Machine\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5AF81036-7117-4222-B135-8D3FF5FB15FC}Machine\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d "1" /f >nul 2>&1
REM ; Disable hidden background speech synthesis updates
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{BF2ED899-C1FF-4DE7-AB82-1FA030853215}Machine\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f >nul 2>&1
REM ; Disable Microsoft experiments
 REG Add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{35671961-DD1D-4609-89CD-2513301BF18D}Machine\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d "0" /f >nul 2>&1
REM ; Disable request verification via feedback
 REG Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{DF69CEE2-D6A1-4079-80C0-53D78FE1EAE0}Machine\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d "1" /f >nul 2>&1
REM ; Disable user behavior recording
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7A44D937-B50E-4B7F-AAA0-983E82B74D7B}Machine\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{715CCCF7-2543-4875-83E2-052829C84ACD}Machine\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{715CCCF7-2543-4875-83E2-052829C84ACD}Machine\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{715CCCF7-2543-4875-83E2-052829C84ACD}Machine\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{01211CE8-BE05-45CA-97B9-9500F8EFA3B0}Machine\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{3E9FACDD-3FB8-48CA-B939-E5525862C392}Machine\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CA7C2EE7-CF2C-4570-AD60-DEB93676E632}Machine\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d "2" /f >nul 2>&1
REM ; Disable user location
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{1EFD6796-AE32-4B9B-99B5-62F09B45F729}Machine\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{1EFD6796-AE32-4B9B-99B5-62F09B45F729}Machine\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d "1" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{BCB17D43-FE3A-4513-8719-756647935A5E}Machine\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A6EE51D2-8871-4C09-9A3D-9C3281B8C724}Machine\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f >nul 2>&1
 REG Add "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >nul 2>&1
:: End
 REG Add "HKCU\Software\Null" /v "TelemetryStatus" /t REG_SZ /d "Disabled" /f >nul 2>&1
 GOTO end
)

ECHO.
%ch% Current Windows Telemetry Status is: {0a}Disabled{\n #}
ECHO.
ECHO Enabling Windows Telemetry...
REM ; Disable Advertising ID and Advertising - Revert
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth" /v "AllowAdvertising" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{E34EF00E-CAE7-4AD7-94E3-87843460B1F9}Machine" /f >nul 2>&1
REM ; Disable all types of Windows syncs - Revert
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mobsync.exe" /f >nul 2>&1
REM ; Disable all Windows and Visual Studio Telemetry - Revert
REG Add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Diagtrack-Listener" /v "Start" /t REG_DWORD /d "1" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /f >nul 2>&1
REG Add "HKLM\System\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
REG Add "HKLM\System\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2" /f >nul 2>&1
REG Add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
REG Add "HKLM\System\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
REG Add "HKLM\System\CurrentControlSet\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
REG Delete "HKLM\System\CurrentControlSet\Policies" /v "telemetry" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "**del.AllowTelemetry" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "**del.CorporateSQMURL" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\AppV\CEIP" /v "CEIPEnable" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7709E9F0-5FED-4252-A59A-ABDEA285E693}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{F10E2328-DE4D-45CE-9E1B-7402EC26D5B4}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CD99AEF9-BC89-4010-AA54-B994270CEF34}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D23106FF-E46C-48D2-968F-87E724E31D90}Machine" /f >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Device Information\Device" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Device Information\Device User" /enable >nul 2>&1
%NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DPS" /V "Start" /T REG_DWORD /D "3" /f >nul 2>&1
%NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiServiceHost" /V "Start" /T REG_DWORD /D "3" /f >nul 2>&1
%NSudo% REG Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdiSystemHost" /V "Start" /T REG_DWORD /D "3" /f >nul 2>&1
REM ; Disable application usage statistics collection - Revert
REG Add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{6A0C3688-2712-48D3-AAB2-610B5DE06793}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A527F628-5DC1-474C-8E24-636BA8CF84E2}Machine" /f >nul 2>&1
REG Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "1" /f >nul 2>&1
schtasks /change /tn "\Microsoft\Windows\Management\Provisioning\Cellular" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Management\Provisioning\Logon" /enable >nul 2>&1
REM ; Disable collection and sending of ink data - Revert
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /f >nul 2>&1
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d "0" /f >nul 2>&1
REG Add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "1" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D700683C-175C-4062-A3BC-12AD216884B3}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A8BBE764-18C0-4D65-AB96-D3964729FD99}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CF7960B7-4399-4457-B22B-AD4708E96690}Machine" /f >nul 2>&1
REM ; Disable collection of data about installed applications - Revert
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{D1B49062-FF05-4294-B5E4-BE9BD0170C2C}Machine" /f >nul 2>&1
REM ; Disable data collection via scheduler events - Revert
schtasks /change /tn \Microsoft\Windows\Maintenance\WinSAT /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Autochk\Proxy" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Application Experience\StartupAppTask" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\PI\Sqm-Tasks" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticResolver" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClient" /enable >nul 2>&1 &schtasks /change /tn "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /enable >nul 2>&1
REM ; Disable Event Log data collection and processing - Revert
REG Add "HKLM\System\CurrentControlSet\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "3" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{E7C22CBD-D40F-47CA-A662-539B5E2CAD41}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{5AF81036-7117-4222-B135-8D3FF5FB15FC}Machine" /f >nul 2>&1
REM ; Disable hidden background speech synthesis updates - Revert
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{BF2ED899-C1FF-4DE7-AB82-1FA030853215}Machine" /f >nul 2>&1
REM ; Disable Microsoft experiments - Revert
REG Delete "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\System" /v "AllowExperimentation" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{35671961-DD1D-4609-89CD-2513301BF18D}Machine" /f >nul 2>&1
REM ; Disable request verification via feedback - Revert
REG Delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{DF69CEE2-D6A1-4079-80C0-53D78FE1EAE0}Machine" /f >nul 2>&1
REM ; Disable user behavior recording - Revert
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AllowTelemetry" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{7A44D937-B50E-4B7F-AAA0-983E82B74D7B}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{715CCCF7-2543-4875-83E2-052829C84ACD}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{01211CE8-BE05-45CA-97B9-9500F8EFA3B0}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{3E9FACDD-3FB8-48CA-B939-E5525862C392}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{CA7C2EE7-CF2C-4570-AD60-DEB93676E632}Machine" /f >nul 2>&1
REM ; Disable user location - Revert
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /f >nul 2>&1
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{1EFD6796-AE32-4B9B-99B5-62F09B45F729}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{BCB17D43-FE3A-4513-8719-756647935A5E}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy Objects\{A6EE51D2-8871-4C09-9A3D-9C3281B8C724}Machine" /f >nul 2>&1
REG Delete "HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /f >nul 2>&1
:: End
REG Add "HKCU\Software\Null" /v "TelemetryStatus" /t REG_SZ /d "Enabled" /f >nul 2>&1
:----------------------------------------------------------------------------:
:end
set end=%time%
set options="tokens=1-4 delims=:.,"
for /f %options% %%a in ("%start%") do set start_h=%%a&set /a start_m=100%%b %% 100&set /a start_s=100%%c %% 100&set /a start_ms=100%%d %% 100
for /f %options% %%a in ("%end%") do set end_h=%%a&set /a end_m=100%%b %% 100&set /a end_s=100%%c %% 100&set /a end_ms=100%%d %% 100
set /a hours=%end_h%-%start_h%
set /a mins=%end_m%-%start_m%
set /a secs=%end_s%-%start_s%
set /a ms=%end_ms%-%start_ms%
if %ms% lss 0 set /a secs = %secs% - 1 & set /a ms = 100%ms%
if %secs% lss 0 set /a mins = %mins% - 1 & set /a secs = 60%secs%
if %mins% lss 0 set /a hours = %hours% - 1 & set /a mins = 60%mins%
if %hours% lss 0 set /a hours = 24%hours%
if 1%ms% lss 100 set ms=0%ms%
:: Mission accomplished
set /a totalsecs = %hours%*3600 + %mins%*60 + %secs%
%ch% Script Took {0c}%hours%:%mins%:%secs%.%ms% (%totalsecs%.%ms%s total){\n #}
pause
exit /b