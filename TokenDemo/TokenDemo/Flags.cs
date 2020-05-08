using System;
using System.Runtime.InteropServices;

namespace TokenDemo
{
    class Flags
    {
        internal const UInt32 DELETE = 0x00010000;
        internal const UInt32 READ_CONTROL = 0x00020000;
        internal const UInt32 SYNCHRONIZE = 0x00100000;
        internal const UInt32 WRITE_DAC = 0x00040000;
        internal const UInt32 WRITE_OWNER = 0x00080000;
        internal const UInt32 PROCESS_ALL_ACCESS = 0;
        internal const UInt32 PROCESS_CREATE_PROCESS = 0x0080;
        internal const UInt32 PROCESS_CREATE_THREAD = 0x0002;
        internal const UInt32 PROCESS_DUP_HANDLE = 0x0040;
        internal const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
        internal const UInt32 PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const UInt32 PROCESS_SET_INFORMATION = 0x0200;
        internal const UInt32 PROCESS_SET_QUOTA = 0x0100;
        internal const UInt32 PROCESS_SUSPEND_RESUME = 0x0800;
        internal const UInt32 PROCESS_TERMINATE = 0x0001;
        internal const UInt32 PROCESS_VM_OPERATION = 0x0008;
        internal const UInt32 PROCESS_VM_READ = 0x0010;
        internal const UInt32 PROCESS_VM_WRITE = 0x0020;
        internal const UInt32 STANDARD_RIGHTS_ALL = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE);
        internal const UInt32 STANDARD_RIGHTS_EXECUTE = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_READ = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_REQUIRED = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER);//0x000F0000;
        internal const UInt32 STANDARD_RIGHTS_WRITE = READ_CONTROL;
        internal const UInt32 TOKEN_ASSIGN_PRIMARY = 0x0001;
        internal const UInt32 TOKEN_DUPLICATE = 0x0002;
        internal const UInt32 TOKEN_IMPERSONATE = 0x0004;
        internal const UInt32 TOKEN_QUERY = 0x0008;
        internal const UInt32 TOKEN_QUERY_SOURCE = 0x0010;
        internal const UInt32 TOKEN_ADJUST_PRIVILEGES = 0x0020;
        internal const UInt32 TOKEN_ADJUST_GROUPS = 0x0040;
        internal const UInt32 TOKEN_ADJUST_DEFAULT = 0x0080;
        internal const UInt32 TOKEN_ADJUST_SESSIONID = 0x0100;
        internal const UInt32 TOKEN_EXECUTE = (STANDARD_RIGHTS_EXECUTE | TOKEN_IMPERSONATE);
        internal const UInt32 TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        internal const UInt32 TOKEN_WRITE = (STANDARD_RIGHTS_READ | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT);
        internal const UInt32 TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        internal const UInt32 TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
        internal const UInt32 TOKEN_ALT2 = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        internal const Int32 ANYSIZE_ARRAY = 1;
        internal const String SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        internal const String SE_BACKUP_NAME = "SeBackupPrivilege";
        internal const String SE_DEBUG_NAME = "SeDebugPrivilege";
        internal const String SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        internal const String SE_TCB_NAME = "SeTcbPrivilege";
        internal const UInt64 SE_GROUP_ENABLED = 0x00000004L;
        internal const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        internal const UInt32 SE_GROUP_INTEGRITY = 0x00000020;
        internal const UInt32 SE_GROUP_INTEGRITY_32 = 0x00000020;
        internal const UInt64 SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
        internal const UInt64 SE_GROUP_LOGON_ID = 0xC0000000L;
        internal const UInt64 SE_GROUP_MANDATORY = 0x00000001L;
        internal const UInt64 SE_GROUP_OWNER = 0x00000008L;
        internal const UInt64 SE_GROUP_RESOURCE = 0x20000000L;
        internal const UInt64 SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;
        internal const UInt32 DISABLE_MAX_PRIVILEGE = 0x1;
        internal const UInt32 SANDBOX_INERT = 0x2;
        internal const UInt32 LUA_TOKEN = 0x4;
        internal const UInt32 WRITE_RESTRICTED = 0x8;

        internal const UInt32 MAXIMUM_ALLOWED = 0x02000000;

        
    }

    enum TOKEN_INFORMATION_CLASS
    {
        TokenUser = 1,
        TokenGroups,
        TokenPrivileges,
        TokenOwner,
        TokenPrimaryGroup,
        TokenDefaultDacl,
        TokenSource,
        TokenType,
        TokenImpersonationLevel,
        TokenStatistics,
        TokenRestrictedSids,
        TokenSessionId,
        TokenGroupsAndPrivileges,
        TokenSessionReference,
        TokenSandBoxInert,
        TokenAuditPolicy,
        TokenOrigin,
        TokenElevationType,
        TokenLinkedToken,
        TokenElevation,
        TokenHasRestrictions,
        TokenAccessInformation,
        TokenVirtualizationAllowed,
        TokenVirtualizationEnabled,
        TokenIntegrityLevel,
        TokenUIAccess,
        TokenMandatoryPolicy,
        TokenLogonSid,
        TokenIsAppContainer,
        TokenCapabilities,
        TokenAppContainerSid,
        TokenAppContainerNumber,
        TokenUserClaimAttributes,
        TokenDeviceClaimAttributes,
        TokenRestrictedUserClaimAttributes,
        TokenRestrictedDeviceClaimAttributes,
        TokenDeviceGroups,
        TokenRestrictedDeviceGroups,
        TokenSecurityAttributes,
        TokenIsRestricted,
        MaxTokenInfoClass
    }

    enum TokenElevationType
    {
        TokenElevationTypeDefault = 1,
        TokenElevationTypeFull,
        TokenElevationTypeLimited
    }

    [Flags]
    public enum SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    };

    [Flags]
    public enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [Flags]
    public enum LOGON_FLAGS
    {
        WithProfile = 1,
        NetCredentialsOnly
    }

    [Flags]
    public enum CREATION_FLAGS : uint
    {
        NONE = 0x0,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_SEPARATE_WOW_VDM = 0x00000800,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public UInt32 cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public UInt32 dwX;
        public UInt32 dwY;
        public UInt32 dwXSize;
        public UInt32 dwYSize;
        public UInt32 dwXCountChars;
        public UInt32 dwYCountChars;
        public UInt32 dwFillAttribute;
        public UInt32 dwFlags;
        public UInt16 wShowWindow;
        public UInt16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public UInt32 dwProcessId;
        public UInt32 dwThreadId;
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [Flags]
    public enum CREATE_FLAGS
    {
        LOGON_WITH_PROFILE = 0x00000001,
        LOGON_NETCREDENTIALS_ONLY = 0x00000002
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LUID
    {
        public UInt32 LowPart;
        public UInt32 HighPart;
    }

    [Flags]
    public enum _SECURITY_IMPERSONATION_LEVEL : int
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    };

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public _LUID TokenId;
        public _LUID AuthenticationId;
        public UInt64 ExpirationTime;
        public TOKEN_TYPE TokenType;
        public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public UInt32 DynamicCharged;
        public UInt32 DynamicAvailable;
        public UInt32 GroupCount;
        public UInt32 PrivilegeCount;
        public _LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _LSA_UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_LOGON_SESSION_DATA
    {
        public UInt32 Size;
        public _LUID LogonId;
        public _LSA_UNICODE_STRING UserName;
        public _LSA_UNICODE_STRING LogonDomain;
        public _LSA_UNICODE_STRING AuthenticationPackage;
        public UInt32 LogonType;
        public UInt32 Session;
        public IntPtr Sid;
        public UInt64 LogonTime;
        public _LSA_UNICODE_STRING LogonServer;
        public _LSA_UNICODE_STRING DnsDomainName;
        public _LSA_UNICODE_STRING Upn;
    }

    [Flags]
    public enum SID_NAME_USE
    {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
        SidTypeLabel
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_IDENTIFIER_AUTHORITY
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
        public Byte[] Value;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public UInt32 Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID_AND_ATTRIBUTES
    {
        public _LUID Luid;
        public UInt32 Attributes;
    }
}
