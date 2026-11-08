using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;

[SupportedOSPlatform("windows")]
internal static class PhantomHostRuntime
{
    private const uint WM_QUERYENDSESSION = 0x0011;
    private const uint WM_ENDSESSION = 0x0016;
    private const uint WM_DESTROY = 0x0002;
    private const uint EWX_RESTARTAPPS = 0x0040;
    private const uint EWX_FORCE = 0x0004;
    private const uint SHTDN_REASON_MAJOR_OTHER = 0x00000000;
    private const uint SHTDN_REASON_MINOR_OTHER = 0x00000000;
    private const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
    private const uint WS_DISABLED = 0x08000000;
    private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
    private const uint TOKEN_QUERY = 0x0008;
    private const uint SE_PRIVILEGE_ENABLED = 0x0002;
    private const string SE_SHUTDOWN_NAME = "SeShutdownPrivilege";

    private static readonly string TracePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PersistLab",
        "phantom_host.log");

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WNDCLASSEX
    {
        public uint cbSize;
        public uint style;
        public IntPtr lpfnWndProc;
        public int cbClsExtra;
        public int cbWndExtra;
        public IntPtr hInstance;
        public IntPtr hIcon;
        public IntPtr hCursor;
        public IntPtr hbrBackground;
        public string? lpszMenuName;
        public string? lpszClassName;
        public IntPtr hIconSm;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public IntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID_AND_ATTRIBUTES Privileges;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern int RegisterApplicationRestart([MarshalAs(UnmanagedType.LPWStr)] string? pwzCommandLine, uint dwFlags);
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);
    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern ushort RegisterClassEx([In] ref WNDCLASSEX lpwcx);
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateWindowEx(uint dwExStyle, string lpClassName, string lpWindowName, uint dwStyle, int x, int y, int nWidth, int nHeight, IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);
    [DllImport("user32.dll")]
    private static extern bool GetMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);
    [DllImport("user32.dll")]
    private static extern bool TranslateMessage([In] ref MSG lpMsg);
    [DllImport("user32.dll")]
    private static extern IntPtr DispatchMessage([In] ref MSG lpmsg);
    [DllImport("user32.dll")]
    private static extern IntPtr DefWindowProc(IntPtr hWnd, uint uMsg, IntPtr wParam, IntPtr lParam);
    [DllImport("user32.dll")]
    private static extern bool PostQuitMessage(int nExitCode);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ShutdownBlockReasonCreate(IntPtr hWnd, [MarshalAs(UnmanagedType.LPWStr)] string pwszReason);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ShutdownBlockReasonDestroy(IntPtr hWnd);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool AbortSystemShutdown(string? lpMachineName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    public static void Run(AuditOptions options)
    {
        string payloadArgs = (options.PhantomPayloadArgs ?? string.Empty).Trim();
        Trace($"Host start scenario='{options.PhantomScenario}' mode='{options.PhantomMode}' args='{payloadArgs}'");
        if (string.IsNullOrWhiteSpace(payloadArgs))
        {
            Trace("Missing --phantom-payload-args, host exit.");
            return;
        }

        string restartHostArgs = BuildHostRestartArgs(options, payloadArgs);
        int hr = RegisterApplicationRestart(restartHostArgs, 0);
        Trace(hr == 0 ? "RegisterApplicationRestart succeeded." : $"RegisterApplicationRestart failed: 0x{hr:X8}");
        
        // Attendre 60 secondes (imposé par Windows)
        Thread.Sleep(60000);
        
        RunMessageLoop();
    }

    private static void RunMessageLoop()
    {
        const string className = "PhantomHost_MessageWindow";
        IntPtr hInstance = GetModuleHandle(null);
        WndProcDelegate wndProc = (hWnd, msg, wParam, lParam) =>
        {
            switch (msg)
            {
                case WM_QUERYENDSESSION:
                    Trace("WM_QUERYENDSESSION received.");
                    ShutdownBlockReasonCreate(hWnd, "PhantomHost scheduling restart...");
                    AbortSystemShutdown(null);
                    EnableShutdownPrivilege();
                    ShutdownBlockReasonDestroy(hWnd);
                    if (!ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER))
                    {
                        Trace($"ExitWindowsEx failed: {Marshal.GetLastWin32Error()}");
                    }
                    else
                    {
                        Trace("ExitWindowsEx(EWX_RESTARTAPPS|EWX_FORCE) succeeded.");
                    }
                    return (IntPtr)1;
                case WM_ENDSESSION:
                    Trace("WM_ENDSESSION received.");
                    ShutdownBlockReasonDestroy(hWnd);
                    return IntPtr.Zero;
                case WM_DESTROY:
                    Trace("WM_DESTROY received.");
                    PostQuitMessage(0);
                    return IntPtr.Zero;
                default:
                    return DefWindowProc(hWnd, msg, wParam, lParam);
            }
        };

        WNDCLASSEX wcex = new()
        {
            cbSize = (uint)Marshal.SizeOf<WNDCLASSEX>(),
            lpfnWndProc = Marshal.GetFunctionPointerForDelegate(wndProc),
            hInstance = hInstance,
            lpszClassName = className
        };

        if (RegisterClassEx(ref wcex) == 0)
        {
            Trace($"RegisterClassEx failed: {Marshal.GetLastWin32Error()}");
            return;
        }

        IntPtr hWnd = CreateWindowEx(0, className, "", WS_OVERLAPPEDWINDOW | WS_DISABLED, 0, 0, 0, 0, IntPtr.Zero, IntPtr.Zero, hInstance, IntPtr.Zero);
        if (hWnd == IntPtr.Zero)
        {
            Trace($"CreateWindowEx failed: {Marshal.GetLastWin32Error()}");
            return;
        }

        Trace("Message loop started.");

        while (GetMessage(out MSG msg, IntPtr.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }

        GC.KeepAlive(wndProc);
    }

    private static void EnableShutdownPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
            return;
        try
        {
            if (!LookupPrivilegeValue(null!, SE_SHUTDOWN_NAME, out LUID luid))
                return;
            TOKEN_PRIVILEGES tp = new()
            {
                PrivilegeCount = 1,
                Privileges = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
            };
            AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static void Trace(string message)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(TracePath) ?? ".");
            File.AppendAllText(TracePath, $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}");
        }
        catch
        {
        }
    }

    private static string BuildHostRestartArgs(AuditOptions options, string payloadArgs)
    {
        string scenario = EscapeForQuotes(options.PhantomScenario ?? "phantom");
        string mode = EscapeForQuotes(options.PhantomMode ?? "all");
        string escapedPayload = EscapeForQuotes(payloadArgs);
        return $"--phantom-host --phantom-scenario \"{scenario}\" --phantom-mode \"{mode}\" --phantom-payload-args \"{escapedPayload}\"";
    }

    private static string EscapeForQuotes(string value) =>
        (value ?? string.Empty).Replace("\\", "\\\\").Replace("\"", "\\\"");
}