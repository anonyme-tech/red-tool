using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

[SupportedOSPlatform("windows")]
internal static class WindowsEffectiveAccess
{
    private const uint MaximumAllowed = 0x02000000;
    private const int ErrorInsufficientBuffer = 122;

    private const uint FileWriteData = 0x0002;
    private const uint FileAppendData = 0x0004;
    private const uint FileWriteEa = 0x0010;
    private const uint FileDeleteChild = 0x0040;
    private const uint FileWriteAttributes = 0x0100;
    private const uint Delete = 0x00010000;
    private const uint WriteDac = 0x00040000;
    private const uint WriteOwner = 0x00080000;

    private const uint FileGenericRead = 0x00120089;
    private const uint FileGenericWrite = 0x00120116;
    private const uint FileGenericExecute = 0x001200A0;
    private const uint FileGenericAll = 0x001F01FF;

    private const uint KeySetValue = 0x0002;
    private const uint KeyCreateSubKey = 0x0004;
    private const uint KeyGenericRead = 0x00020019;
    private const uint KeyGenericWrite = 0x00020006;
    private const uint KeyGenericExecute = 0x00020019;
    private const uint KeyGenericAll = 0x000F003F;

    private const uint DangerousFileAccessMask =
        FileWriteData |
        FileAppendData |
        FileWriteEa |
        FileWriteAttributes |
        Delete |
        WriteDac |
        WriteOwner;

    private const uint DangerousDirectoryAccessMask =
        FileWriteData |
        FileAppendData |
        FileDeleteChild |
        Delete |
        WriteDac |
        WriteOwner;

    private const uint DangerousRegistryAccessMask =
        KeySetValue |
        KeyCreateSubKey |
        Delete |
        WriteDac |
        WriteOwner;

    private static readonly GenericMapping FileGenericMapping = new()
    {
        GenericRead = FileGenericRead,
        GenericWrite = FileGenericWrite,
        GenericExecute = FileGenericExecute,
        GenericAll = FileGenericAll
    };

    private static readonly GenericMapping RegistryGenericMapping = new()
    {
        GenericRead = KeyGenericRead,
        GenericWrite = KeyGenericWrite,
        GenericExecute = KeyGenericExecute,
        GenericAll = KeyGenericAll
    };

    public static bool HasFileWriteAccess(FileSecurity security) =>
        HasAccess(security.GetSecurityDescriptorBinaryForm(), FileGenericMapping, DangerousFileAccessMask);

    public static bool HasDirectoryWriteAccess(DirectorySecurity security) =>
        HasAccess(security.GetSecurityDescriptorBinaryForm(), FileGenericMapping, DangerousDirectoryAccessMask);

    public static bool HasRegistryWriteAccess(RegistrySecurity security) =>
        HasAccess(security.GetSecurityDescriptorBinaryForm(), RegistryGenericMapping, DangerousRegistryAccessMask);

    private static bool HasAccess(byte[] securityDescriptor, GenericMapping genericMapping, uint dangerousAccessMask)
    {
        using SafeAccessTokenHandle token = DuplicateCurrentTokenForAccessCheck();

        uint privilegeSetLength = 256;
        IntPtr privilegeSet = Marshal.AllocHGlobal((int)privilegeSetLength);

        try
        {
            while (true)
            {
                GenericMapping mapping = genericMapping;
                bool accessCheckResult = AccessCheck(
                    securityDescriptor,
                    token,
                    MaximumAllowed,
                    ref mapping,
                    privilegeSet,
                    ref privilegeSetLength,
                    out uint grantedAccess,
                    out bool accessStatus);

                if (accessCheckResult)
                {
                    return accessStatus && (grantedAccess & dangerousAccessMask) != 0;
                }

                int error = Marshal.GetLastWin32Error();
                if (error == ErrorInsufficientBuffer)
                {
                    privilegeSet = Marshal.ReAllocHGlobal(privilegeSet, (IntPtr)privilegeSetLength);
                    continue;
                }

                throw new Win32Exception(error);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(privilegeSet);
        }
    }

    private static SafeAccessTokenHandle DuplicateCurrentTokenForAccessCheck()
    {
        using WindowsIdentity identity = WindowsIdentity.GetCurrent(TokenAccessLevels.Query | TokenAccessLevels.Duplicate);

        if (!DuplicateTokenEx(
            identity.AccessToken,
            (uint)TokenAccessLevels.Query,
            IntPtr.Zero,
            SecurityImpersonationLevel.SecurityImpersonation,
            TokenType.TokenImpersonation,
            out SafeAccessTokenHandle duplicatedToken))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        return duplicatedToken;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AccessCheck(
        byte[] pSecurityDescriptor,
        SafeAccessTokenHandle clientToken,
        uint desiredAccess,
        ref GenericMapping genericMapping,
        IntPtr privilegeSet,
        ref uint privilegeSetLength,
        out uint grantedAccess,
        [MarshalAs(UnmanagedType.Bool)] out bool accessStatus);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        SafeAccessTokenHandle existingToken,
        uint desiredAccess,
        IntPtr tokenAttributes,
        SecurityImpersonationLevel impersonationLevel,
        TokenType tokenType,
        out SafeAccessTokenHandle newToken);

    [StructLayout(LayoutKind.Sequential)]
    private struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    private enum SecurityImpersonationLevel
    {
        SecurityAnonymous = 0,
        SecurityIdentification = 1,
        SecurityImpersonation = 2,
        SecurityDelegation = 3
    }

    private enum TokenType
    {
        TokenPrimary = 1,
        TokenImpersonation = 2
    }
}
