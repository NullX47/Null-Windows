@echo off
@setlocal
Color 0f
chcp 65001 > nul
SetLocal EnableExtensions EnableDelayedExpansion
pushd "%CD%" & CD /D "%~dp0" >nul
REG Query "HKU\S-1-5-19" >nul 2>&1 || "Work\nircmd.exe" elevate "%~f0" && exit
set start=%time%
set "ch=Work\cecho.exe"
set "NSudo=Work\NSudoLC.exe -U:T -P:E -ShowWindowMode:Hide -Wait cmd.exe /c"
set "HIVE=SYSTEM\CurrentControlSet"
set "serviceswebmask="
for /f "usebackq delims=" %%n In (`2^>nul REG Query "HKLM\%HIVE%\Services" /f "webthreatdefusersvc*" /k^|findstr ^H`) do set serviceswebmask=%%~nxn
if defined serviceswebmask (Mode 82,44) else (Mode 80,44)
"Work\nircmd.exe" win center process cmd.exe & "Work\nircmd.exe" win settext foreground "Null.Script.For.Windows.Services"
:----------------------------------------------------------------------------:
REM ; Check that there are no parentheses in the path
    if not exist "Work" echo The Work folder was not found, you will be exited. && timeout /t 7 >nul && exit
    echo "%~dp0" | findstr /c:"(" /c:")" > nul && echo The path to .bat contains brackets, correct the path and run the script again. && timeout /t 7 >nul && exit
REM ; Start
    REG Query "HKCU\Software\Null" /v "ServicesStatus" >nul 2>&1 && echo already added >nul 2>&1 || REG Add "HKCU\Software\Null" /v "ServicesStatus" /t REG_SZ /d "Default" /f >nul 2>&1
    REG Query HKCU\Software\Null /v ServicesStatus | find "REG_SZ" | find "Default" >nul 2>&1
    if "%ERRORLEVEL%"=="0" (
    ECHO.
    %ch% Current Windows Services Configuration is: {0c}Default{\n #}
    ECHO.
    ECHO Applying Null Windows Services Configuration...
	timeout /t 3 >nul
REM ; i don't use Microsoft virtual machines
:--------------------
for %%X in (vmicvmsession vmictimesync vmicshutdown vmicrdv vmickvpexchange vmicheartbeat vmicguestinterface vmicvss hvservice HvHost) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't record games and broadcasts using Windows itself
for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
:--------------------------------------
REM ; i don't change the Internet configs, it is already working
:--------------------
for %%X in (NcaSvc SSDPSRV wcncsvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use the Windows Store and its apps
:--------------------
for %%X in (WalletService VacSvc spectrum SharedRealitySvc perceptionsimulation MixedRealityOpenXRSvc MapsBroker EntAppSvc embeddedmode wlidsvc WEPHOSTSVC StorSvc ClipSVC InstallService RetailDemo NcbService TokenBroker LicenseManager) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
	)
)
:--------------------------------------
REM ; i don't use passwords when logging in to my Windows account
:--------------------
for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "CredentialEnrollmentManagerUserSvc" ^| find /i "CredentialEnrollmentManagerUserSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
:--------------------------------------
REM ; i don't use biometrics (fingerprint, face recognition)
:--------------------
REG Add "HKLM\%HIVE%\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use Bluetooth devices (mouse, speakers, headphones)
:--------------------
for %%X in (bthserv BthAvctpSvc BTAGService) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "ConsentUxUserSvc" ^| find /i "ConsentUxUserSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "BluetoothUserService" ^| find /i "BluetoothUserService"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
	)
)
:--------------------------------------
REM ; i don't use anything from Xbox, neither controller, nor Xbox game saves
:--------------------
for %%X in (XboxNetApiSvc xboxgip XboxGipSvc XblGameSave XblAuthManager) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "DeviceAssociationBrokerSvc" ^| find /i "DeviceAssociationBrokerSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
	)
)
:--------------------------------------
REM ; i don't use a printer, neither virtual, nor networked, nor local
:--------------------
for %%X in (Spooler PrintNotify McpManagementService) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "PrintWorkflowUserSvc" ^| find /i "PrintWorkflowUserSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
	)
)
:--------------------------------------
REM ; i don't use scanner, neither virtual, nor networked, nor local
:--------------------
for %%X in (WiaRpc stisvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use a fax, neither virtual, nor networked, nor local
:--------------------
for %%X in (PhoneSvc Fax TapiSrv SmsRouter) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Windows updates and install the components myself
:--------------------
for %%X in (wisvc DmEnrollmentSvc wuauserv WaaSMedicSvc DoSvc UsoSvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use tablet mode, i have a desktop/laptop
:--------------------
for %%X in (SensrSvc SensorService SensorDataService SEMgrSvc lfsvc TabletInputService) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use wireless or additional monitors
:--------------------
for %%X in (DispBrokerDesktopSvc WFDSConMgrSvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Virtual Desktops, Night Light, Your Phone
:--------------------
for %%X in (CDPSvc PushToInstall WpnService) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "CDPUserSvc" ^| find /i "CDPUserSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
		for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
	)
)
:--------------------------------------
REM ; i don't use Windows Themes / use, but don't change
:--------------------
REG Add "HKLM\%HIVE%\Services\Themes" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use USB modems or USB routers
:--------------------
for %%X in (WwanSvc wlpasvc icssvc DusmSvc autotimesvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use LAN (neither wired, nor wireless)
:--------------------
for %%X in (Netlogon CscService lmhosts FDResPub fdPHost Dnscache LanmanServer LanmanWorkstation) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use VPN (special VPN clients)
:--------------------
for %%X in (PolicyAgent IKEEXT p2pimsvc Eaphost) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use anything related to Windows Media
:--------------------
for %%X in (WPDBusEnum WMPNetworkSvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't allow remote control of my computer
:--------------------
for %%X in (UmRdpService TermService SessionEnv DsSvc RemoteRegistry) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't collect bug reports
:--------------------
for %%X in (WerSvc wercplsupport Wecsvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Clouds via WebDAV / idk what it is
:--------------------
REG Add "HKLM\%HIVE%\Services\WebClient" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use Smart cards / idk what it is
:--------------------
for %%X in (SCPolicySvc ScDeviceEnum SCardSvr CertPropSvc scfilter) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Windows Kiosk / idk what it is
:--------------------
for %%X in (AssignedAccessManagerSvc AppReadiness) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Windows File History / idk what it is
:--------------------
for %%X in (fhsvc WSearch WMPNetworkSvc workfolderssvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use encryption of files, folders, drives
:--------------------
for %%X in (EFS BDESVC) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Windows localizations, except for the existing ones
:--------------------
REG Add "HKLM\%HIVE%\Services\LxpSvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't need a background security scan from Microsoft
:--------------------
for %%X in (WarpJITSvc wscsvc) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Windows performance counters
:--------------------
for %%X in (wmiApSrv pla PerfHost) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't need background computer diagnostics
:--------------------
for %%X in (WdiSystemHost WdiServiceHost TroubleshootingSvc DPS diagnosticshub.standardcollector.service diagsvc DiagTrack) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		%NSudo% REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use corporate Windows management tools
:--------------------
for %%X in (workfolderssvc SNMPTRAP RemoteRegistry Netlogon EntAppSvc dot3svc DevQueryBroker AppMgmt) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:--------------------------------------
REM ; i don't use Time Sync Service
:--------------------
REG Add "HKLM\%HIVE%\Services\W32Time" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use Radio
:--------------------
REG Add "HKLM\%HIVE%\Services\RmSvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use AJRouter
:--------------------
REG Add "HKLM\%HIVE%\Services\AJRouter" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't use Superfetch
:--------------------
REG Add "HKLM\%HIVE%\Services\SysMain" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; i don't need Notifications
:--------------------
REG Add "HKLM\%HIVE%\Services\SENS" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; Shell Autostart Service
:--------------------
REG Add "HKLM\%HIVE%\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; Software Compatibility Assistant
:--------------------
REG Add "HKLM\%HIVE%\Services\PcaSvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; DevicesFlow Services
:--------------------
for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "DevicesFlowUserSvc" ^| find /i "DevicesFlowUserSvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
:--------------------------------------
REM ; WpnUserService
:--------------------
for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "WpnUserService" ^| find /i "WpnUserService"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
:--------------------------------------
REM ; IPv6 Tunneling Service
:--------------------
REG Add "HKLM\%HIVE%\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; Push Message Routing
:--------------------
REG Add "HKLM\%HIVE%\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; Defragmentation Service
:--------------------
REG Add "HKLM\%HIVE%\Services\defragsvc" /v "Start" /t REG_DWORD /d "4" /f
:--------------------------------------
REM ; Clipboard Services
:--------------------
for /f %%Z in ('REG Query "HKLM\%HIVE%\Services" /k /f "cbdhsvc" ^| find /i "cbdhsvc"') do (REG Add "%%Z" /v "Start" /t reg_dword /d 4 /f)
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d "0" /f
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f
REG Add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowCrossDeviceClipboard" /t REG_DWORD /d "0" /f
:--------------------------------------
REM ; Font Cache Service
:--------------------
for %%X in (FontCache FontCache3.0.0.0) do (
	REG Query "HKLM\%HIVE%\Services\%%X" /ve >nul 2>&1
	if %errorlevel% == 0 (
		REG Add "HKLM\%HIVE%\Services\%%X" /v "Start" /t REG_DWORD /d "4" /f
	)
)
:: End
REG Add "HKCU\Software\Null" /v "ServicesStatus" /t REG_SZ /d "Null" /f >nul 2>&1
GOTO end
)
REM ; Start - Revert
    ECHO.
    %ch% Current Windows Services Configuration is: {0a}Null{\n #}
    ECHO.
    ECHO Applying Default Windows Services Configuration...
REM ; TI
	if /i "%USERNAME%" neq "%COMPUTERNAME%$" Work\NSudoLC.exe -U:T -P:E -UseCurrentConsole -Priority:High %0 && exit
	timeout /t 3 >nul
    REG Add "HKLM\%HIVE%\Services\AJRouter" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ALG" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AppIDSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Appinfo" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AppMgmt" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AppReadiness" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AppVClient" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\AppXSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AssignedAccessManagerSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AudioEndpointBuilder" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\Audiosrv" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\autotimesvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AxInstSV" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BDESVC" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BFE" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\BITS" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BrokerInfrastructure" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\BTAGService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BthAvctpSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\bthserv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\camsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\CDPSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\CertPropSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ClipSVC" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\cloudidsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\COMSysApp" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\CoreMessagingRegistrar" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\CryptSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\CscService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DcomLaunch" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\dcsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\defragsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DeviceAssociationService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DeviceInstall" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DevQueryBroker" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Dhcp" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\diagnosticshub.standardcollector.service" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\DialogBlockingService" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\DispBrokerDesktopSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\DisplayEnhancementService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DmEnrollmentSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Dnscache" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\DoSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\dot3svc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DPS" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\DsmSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DsSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DusmSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\Eaphost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\edgeupdate" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\edgeupdatem" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\EFS" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\embeddedmode" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\EntAppSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\EventLog" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\EventSystem" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\Fax" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\fdPHost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\FDResPub" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\fhsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\FontCache" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\FrameServer" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\GameInputSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\gpsvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\hidserv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\HvHost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\icssvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\IKEEXT" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\InstallService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\iphlpsvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\IpxlatCfgSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\KeyIso" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\KtmRm" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\LanmanServer" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\LanmanWorkstation" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\lfsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\LicenseManager" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\lltdsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\lmhosts" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\LSM" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\LxpSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MapsBroker" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\McpManagementService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MicrosoftEdgeElevationService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MixedRealityOpenXRSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\mpssvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\MSDTC" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MSiSCSI" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\msiserver" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MsKeyboardFilter" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\NaturalAuthentication" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NcaSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NcbService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NcdAutoSetup" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Netlogon" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Netman" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\netprofm" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NetSetupSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NetTcpPortSharing" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\NgcCtnrSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NgcSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\NlaSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\nsi" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\p2pimsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\p2psvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PcaSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PeerDistSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\perceptionsimulation" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PerfHost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PhoneSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\pla" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PlugPlay" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PNRPAutoReg" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PNRPsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PolicyAgent" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Power" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\PrintNotify" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ProfSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\PushToInstall" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\QWAVE" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RasAuto" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RasMan" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RemoteAccess" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\RetailDemo" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RmSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RpcEptMapper" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\RpcLocator" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\RpcSs" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SamSs" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SCardSvr" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ScDeviceEnum" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Schedule" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SCPolicySvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SDRSVC" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\seclogon" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SEMgrSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SENS" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\Sense" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SensorDataService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SensorService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SensrSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SessionEnv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SgrmBroker" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SharedAccess" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SharedRealitySvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ShellHWDetection" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\shpamsvc" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\smphost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SmsRouter" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SNMPTRAP" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\spectrum" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Spooler" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\sppsvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SSDPSRV" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\ssh-agent" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\SstpSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\StateRepository" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\stisvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\StorSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\svsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\swprv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\SysMain" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\SystemEventsBroker" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\TabletInputService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\TapiSrv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\TermService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Themes" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\TieringEngineService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\TimeBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\TokenBroker" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\TrkWks" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\TroubleshootingSvc" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\TrustedInstaller" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\tzautoupdate" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\UevAgentService" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\UmRdpService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\upnphost" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\UserManager" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\UsoSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\VacSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\VaultSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vds" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\VGAuthService" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\vm3dservice" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\vmicguestinterface" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmicheartbeat" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmickvpexchange" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmicrdv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmicshutdown" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmictimesync" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmicvmsession" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\vmicvss" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\VMTools" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\vmvss" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\VSS" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\W32Time" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WaaSMedicSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WalletService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WarpJITSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wbengine" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WbioSrvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Wcmsvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\wcncsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WdiServiceHost" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\WdiSystemHost" /v "Start" /t REG_DWORD /d "4" /f
    REG Add "HKLM\%HIVE%\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WebClient" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Wecsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WEPHOSTSVC" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wercplsupport" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WerSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WFDSConMgrSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WiaRpc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WinDefend" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\Winmgmt" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\WinRM" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wisvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WlanSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wlidsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wlpasvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WManSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\wmiApSrv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WMPNetworkSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\workfolderssvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WpcMonSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WPDBusEnum" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WpnService" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\wscsvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\WSearch" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\wuauserv" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WwanSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\XblAuthManager" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\XblGameSave" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\XboxGipSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\AarSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\BluetoothUserService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\CaptureService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\cbdhsvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\CDPUserSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\ConsentUxUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\CredentialEnrollmentManagerUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DeviceAssociationBrokerSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DevicePickerUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\DevicesFlowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\MessagingService" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d "2" /f
    REG Add "HKLM\%HIVE%\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\PrintWorkflowUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\UdkUserSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\UnistoreSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\UserDataSvc" /v "Start" /t REG_DWORD /d "3" /f
    REG Add "HKLM\%HIVE%\Services\WpnUserService" /v "Start" /t REG_DWORD /d "2" /f
:: End - Revert
    REG Add "HKCU\Software\Null" /v "ServicesStatus" /t REG_SZ /d "Default" /f >nul 2>&1
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
%ch% Script Took {04}%hours%:%mins%:%secs%.%ms% (%totalsecs%.%ms%s total){\n #}
pause
exit /b