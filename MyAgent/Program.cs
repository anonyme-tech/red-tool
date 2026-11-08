using System.Runtime.Versioning;

[SupportedOSPlatform("windows")]
internal static class Program
{
    private static readonly string StartupTracePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PersistLab",
        "myagent_startup.log");

    public static int Main(string[] args)
    {
        TraceStartup(args);

        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("[X] This tool only runs on Windows.");
            return 1;
        }

        ArgumentParseResult parseResult = AuditOptions.Parse(args);
        if (!parseResult.Success)
        {
            Console.Error.WriteLine($"[X] {parseResult.ErrorMessage}");
            Console.Error.WriteLine();
            AuditOptions.PrintUsage();
            return 1;
        }

        if (parseResult.ShowHelp || parseResult.Options is null)
        {
            AuditOptions.PrintUsage();
            return 0;
        }

        try
        {
            if (parseResult.Options.PhantomHost)
            {
                PhantomHostRuntime.Run(parseResult.Options);
                return 0;
            }

            if (parseResult.Options.ShellOnly)
            {
                InteractiveShellClient.RunStandalone(parseResult.Options);
                return 0;
            }

            var scanner = new WindowsAuditScanner(parseResult.Options);
            AuditReport report = scanner.Run();

            ReportWriter.Write(report, parseResult.Options);
            AuditUploadClient.UploadIfConfigured(report, parseResult.Options);
            InteractiveShellClient.RunIfConfigured(report, parseResult.Options);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"[X] Fatal error: {ex.Message}");
            return 1;
        }
    }

    private static void TraceStartup(string[] args)
    {
        try
        {
            string dir = Path.GetDirectoryName(StartupTracePath) ?? ".";
            Directory.CreateDirectory(dir);
            string argLine = string.Join(" ", args ?? Array.Empty<string>());
            string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] pid={Environment.ProcessId} exe='{Environment.ProcessPath}' args='{argLine}'{Environment.NewLine}";
            File.AppendAllText(StartupTracePath, line);
        }
        catch
        {
            // Never break runtime on trace failure.
        }
    }
}