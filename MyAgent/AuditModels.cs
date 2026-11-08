using System.Globalization;
using System.Runtime.Versioning;

[SupportedOSPlatform("windows")]
internal enum OutputFormat
{
    Console,
    Json,
    Csv
}

[SupportedOSPlatform("windows")]
internal enum Severity
{
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3
}

[SupportedOSPlatform("windows")]
internal sealed record AuditOptions(
    bool Verbose,
    OutputFormat Format,
    string? OutputPath,
    string? ServerUrl,
    string? ListenerId,
    string? AgentId,
    int UploadTimeoutSeconds,
    bool InteractiveShell,
    bool ShellOnly,
    int ShellPollSeconds,
    int ShellCommandTimeoutSeconds,
    bool PhantomHost,
    string? PhantomScenario,
    string? PhantomMode,
    string? PhantomPayloadArgs)
{
    public bool UploadEnabled =>
        !string.IsNullOrWhiteSpace(ServerUrl) || !string.IsNullOrWhiteSpace(ListenerId);

    public static ArgumentParseResult Parse(string[] args)
    {
        bool verbose = false;
        OutputFormat format = OutputFormat.Console;
        string? outputPath = null;
        string? serverUrl = null;
        string? listenerId = null;
        string? agentId = null;
        int uploadTimeoutSeconds = 15;
        bool interactiveShell = false;
        bool shellOnly = false;
        int shellPollSeconds = 2;
        int shellCommandTimeoutSeconds = 120;
        bool phantomHost = false;
        string? phantomScenario = null;
        string? phantomMode = null;
        string? phantomPayloadArgs = null;
        bool showHelp = false;

        for (int index = 0; index < args.Length; index++)
        {
            string arg = args[index];

            switch (arg.ToLowerInvariant())
            {
                case "-v":
                case "--verbose":
                    verbose = true;
                    break;
                case "--json":
                    format = OutputFormat.Json;
                    break;
                case "--csv":
                    format = OutputFormat.Csv;
                    break;
                case "--format":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --format.");
                    }

                    index++;
                    if (!Enum.TryParse(args[index], ignoreCase: true, out format))
                    {
                        return ArgumentParseResult.Fail($"Unsupported format '{args[index]}'.");
                    }

                    break;
                case "-o":
                case "--output":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --output.");
                    }

                    outputPath = args[++index];
                    break;
                case "--server":
                case "--upload-server":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --server.");
                    }

                    serverUrl = args[++index];
                    break;
                case "--listener":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --listener.");
                    }

                    listenerId = args[++index];
                    break;
                case "--agent-id":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --agent-id.");
                    }

                    agentId = args[++index];
                    break;
                case "--upload-timeout":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --upload-timeout.");
                    }

                    if (!int.TryParse(args[++index], out uploadTimeoutSeconds) || uploadTimeoutSeconds < 1)
                    {
                        return ArgumentParseResult.Fail("Invalid value for --upload-timeout.");
                    }

                    break;
                case "--shell":
                case "--interactive-shell":
                    interactiveShell = true;
                    break;
                case "--shell-only":
                    shellOnly = true;
                    interactiveShell = true;
                    break;
                case "--shell-poll":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --shell-poll.");
                    }

                    if (!int.TryParse(args[++index], out shellPollSeconds) || shellPollSeconds < 1 || shellPollSeconds > 60)
                    {
                        return ArgumentParseResult.Fail("Invalid value for --shell-poll (1-60).");
                    }

                    break;
                case "--shell-timeout":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --shell-timeout.");
                    }

                    if (!int.TryParse(args[++index], out shellCommandTimeoutSeconds) || shellCommandTimeoutSeconds < 5 || shellCommandTimeoutSeconds > 3600)
                    {
                        return ArgumentParseResult.Fail("Invalid value for --shell-timeout (5-3600).");
                    }

                    break;
                case "--phantom-host":
                    phantomHost = true;
                    break;
                case "--phantom-scenario":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --phantom-scenario.");
                    }
                    phantomScenario = args[++index];
                    break;
                case "--phantom-mode":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --phantom-mode.");
                    }
                    phantomMode = args[++index];
                    break;
                case "--phantom-payload-args":
                    if (index + 1 >= args.Length)
                    {
                        return ArgumentParseResult.Fail("Missing value after --phantom-payload-args.");
                    }
                    phantomPayloadArgs = args[++index];
                    break;
                case "-h":
                case "--help":
                    showHelp = true;
                    break;
                default:
                    return ArgumentParseResult.Fail($"Unknown argument '{arg}'.");
            }
        }

        if (string.IsNullOrWhiteSpace(serverUrl) != string.IsNullOrWhiteSpace(listenerId))
        {
            return ArgumentParseResult.Fail("Both --server and --listener are required for HTTP upload.");
        }

        return new ArgumentParseResult(
            true,
            null,
            showHelp,
            new AuditOptions(
                verbose,
                format,
                outputPath,
                serverUrl,
                listenerId,
                agentId,
                uploadTimeoutSeconds,
                interactiveShell,
                shellOnly,
                shellPollSeconds,
                shellCommandTimeoutSeconds,
                phantomHost,
                phantomScenario,
                phantomMode,
                phantomPayloadArgs));
    }

    public static void PrintUsage()
    {
        Console.WriteLine("Windows Security Audit Tool");
        Console.WriteLine();
        Console.WriteLine("Usage:");
        Console.WriteLine("  MyAgent.exe [--verbose] [--json|--csv|--format console|json|csv] [--output <path>]");
        Console.WriteLine("             [--server <url> --listener <listener_id>] [--agent-id <value>] [--upload-timeout <seconds>]");
        Console.WriteLine("             [--shell|--shell-only] [--shell-poll <seconds>] [--shell-timeout <seconds>]");
        Console.WriteLine("             [--phantom-host --phantom-scenario <name> --phantom-mode <mode> --phantom-payload-args \"<args>\"]");
        Console.WriteLine();
        Console.WriteLine("Options:");
        Console.WriteLine("  -v, --verbose        Show diagnostic messages");
        Console.WriteLine("  --json               Export JSON report");
        Console.WriteLine("  --csv                Export CSV report");
        Console.WriteLine("  --format <value>     Output format: console, json, csv");
        Console.WriteLine("  -o, --output <path>  Custom output file path");
        Console.WriteLine("  --server <url>       Upload the JSON report to the dashboard API (http/https, any host)");
        Console.WriteLine("  --listener <id>      Listener ID used for the HTTP upload");
        Console.WriteLine("  --agent-id <value>   Optional stable agent identifier for uploads");
        Console.WriteLine("  --upload-timeout <s> HTTP upload timeout in seconds");
        Console.WriteLine("  --shell              Enable remote interactive shell polling loop");
        Console.WriteLine("  --shell-only         Start only shell loop (skip audit scan/report/upload)");
        Console.WriteLine("  --shell-poll <s>     Delay between shell polls when idle (1-60)");
        Console.WriteLine("  --shell-timeout <s>  Max runtime for one shell command (5-3600)");
        Console.WriteLine("  --phantom-host       Run dedicated phantom host runtime");
        Console.WriteLine("  --phantom-scenario   Scenario name used by phantom host logs");
        Console.WriteLine("  --phantom-mode       Trigger mode used by phantom host logs");
        Console.WriteLine("  --phantom-payload-args  Args to relaunch payload (typically --shell-only ...)");
        Console.WriteLine("  -h, --help           Show this help");
    }
}

[SupportedOSPlatform("windows")]
internal sealed record ArgumentParseResult(
    bool Success,
    string? ErrorMessage,
    bool ShowHelp,
    AuditOptions? Options)
{
    public static ArgumentParseResult Fail(string message) =>
        new(false, message, false, null);
}

[SupportedOSPlatform("windows")]
internal sealed record SystemProfile(
    string MachineName,
    string UserName,
    string Domain,
    string OsVersion,
    bool IsAdministrator,
    IReadOnlyList<string> IPv4Addresses,
    string? CpuName,
    int? CpuCoreCount,
    ulong? TotalMemoryMb);

[SupportedOSPlatform("windows")]
internal sealed record VulnerabilityFinding(
    string Type,
    string Target,
    Severity Severity,
    string Description,
    string EvidencePath,
    string Category,
    string? Principal = null,
    string? State = null);

[SupportedOSPlatform("windows")]
internal sealed record AuditReport(
    DateTimeOffset Timestamp,
    SystemProfile System,
    IReadOnlyList<VulnerabilityFinding> Findings,
    IReadOnlyList<string> Warnings)
{
    public string RiskLevel => AuditRiskCalculator.GetRiskLevel(Findings);
}

[SupportedOSPlatform("windows")]
internal static class AuditRiskCalculator
{
    public static string GetRiskLevel(IEnumerable<VulnerabilityFinding> findings)
    {
        int critical = findings.Count(item => item.Severity == Severity.Critical);
        int high = findings.Count(item => item.Severity == Severity.High);
        int medium = findings.Count(item => item.Severity == Severity.Medium);

        if (critical > 0)
        {
            return "CRITICAL";
        }

        if (high >= 2)
        {
            return "HIGH";
        }

        if (high > 0 || medium >= 3)
        {
            return "MEDIUM";
        }

        return "LOW";
    }
}

[SupportedOSPlatform("windows")]
internal static class SeverityExtensions
{
    public static string ToDisplayString(this Severity severity) =>
        severity.ToString().ToUpperInvariant();

    public static string ToCsvString(this Severity severity) =>
        severity.ToString().ToUpper(CultureInfo.InvariantCulture);
}