using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using Microsoft.Win32;

[SupportedOSPlatform("windows")]
internal sealed class WindowsAuditScanner
{
    private readonly AuditOptions _options;
    private readonly List<VulnerabilityFinding> _findings = new();
    private readonly List<string> _warnings = new();
    private readonly HashSet<string> _dedupeKeys = new(StringComparer.OrdinalIgnoreCase);

    public WindowsAuditScanner(AuditOptions options)
    {
        _options = options;
    }

    public AuditReport Run()
    {
        Log("Collecting system profile...");
        SystemProfile system = CollectSystemProfile();

        Log("Scanning Windows services...");
        ScanServices();

        Log("Scanning scheduled tasks...");
        ScanScheduledTasks();

        Log("Scanning sensitive registry keys...");
        ScanRegistryKeys();

        IReadOnlyList<VulnerabilityFinding> orderedFindings = _findings
            .OrderByDescending(item => item.Severity)
            .ThenBy(item => item.Category, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Target, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new AuditReport(
            DateTimeOffset.Now,
            system,
            orderedFindings,
            _warnings.ToList());
    }

    private SystemProfile CollectSystemProfile()
    {
        bool isAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

        string? cpuName = null;
        int? cpuCoreCount = null;
        ulong? totalMemoryMb = null;

        try
        {
            using var cpuSearcher = new ManagementObjectSearcher("SELECT Name, NumberOfCores FROM Win32_Processor");
            foreach (ManagementObject item in cpuSearcher.Get().OfType<ManagementObject>())
            {
                cpuName = item["Name"]?.ToString();
                cpuCoreCount = TryConvertInt(item["NumberOfCores"]);
                break;
            }
        }
        catch (Exception ex)
        {
            AddWarning($"Unable to read CPU information: {ex.Message}");
        }

        try
        {
            using var memorySearcher = new ManagementObjectSearcher("SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem");
            foreach (ManagementObject item in memorySearcher.Get().OfType<ManagementObject>())
            {
                if (item["TotalVisibleMemorySize"] is ulong totalVisibleMemoryKb)
                {
                    totalMemoryMb = totalVisibleMemoryKb / 1024;
                }

                break;
            }
        }
        catch (Exception ex)
        {
            AddWarning($"Unable to read memory information: {ex.Message}");
        }

        return new SystemProfile(
            Environment.MachineName,
            Environment.UserName,
            Environment.UserDomainName,
            Environment.OSVersion.ToString(),
            isAdministrator,
            GetIPv4Addresses(),
            cpuName,
            cpuCoreCount,
            totalMemoryMb);
    }

    private void ScanServices()
    {
        const string query = "SELECT Name, DisplayName, PathName, StartName, State FROM Win32_Service";

        try
        {
            using var searcher = new ManagementObjectSearcher(query);
            foreach (ManagementObject service in searcher.Get().OfType<ManagementObject>())
            {
                string name = service["Name"]?.ToString() ?? "(unknown)";
                string displayName = service["DisplayName"]?.ToString() ?? name;
                string commandLine = service["PathName"]?.ToString() ?? string.Empty;
                string principal = service["StartName"]?.ToString() ?? "Unknown";
                string state = service["State"]?.ToString() ?? "Unknown";

                if (string.IsNullOrWhiteSpace(commandLine))
                {
                    continue;
                }

                string? executablePath = WindowsPathHelper.ExtractExecutablePath(commandLine);
                if (string.IsNullOrWhiteSpace(executablePath))
                {
                    AddWarning($"Unable to parse service path for '{displayName}'.");
                    continue;
                }

                string expandedExecutablePath = WindowsPathHelper.NormalizePath(executablePath);
                bool privileged = WindowsSecurityHelper.IsPrivilegedPrincipal(principal);
                string target = $"{displayName} ({name})";

                if (WindowsPathHelper.IsUnquotedExecutablePath(commandLine))
                {
                    AddFinding(new VulnerabilityFinding(
                        "Unquoted Service Path",
                        target,
                        privileged ? Severity.High : Severity.Medium,
                        "The service executable path contains spaces and is not quoted.",
                        commandLine,
                        "Service",
                        principal,
                        state));
                }

                if (File.Exists(expandedExecutablePath) &&
                    WindowsSecurityHelper.IsFileWritableByCurrentIdentity(expandedExecutablePath))
                {
                    AddFinding(new VulnerabilityFinding(
                        "Writable Service Binary",
                        target,
                        privileged ? Severity.Critical : Severity.High,
                        "The service executable is writable by the current identity.",
                        expandedExecutablePath,
                        "Service",
                        principal,
                        state));
                }

                string? directoryPath = Path.GetDirectoryName(expandedExecutablePath);
                if (!string.IsNullOrWhiteSpace(directoryPath) &&
                    Directory.Exists(directoryPath) &&
                    WindowsSecurityHelper.IsDirectoryWritableByCurrentIdentity(directoryPath))
                {
                    AddFinding(new VulnerabilityFinding(
                        "Writable Service Directory",
                        target,
                        privileged ? Severity.High : Severity.Medium,
                        "The directory containing the service executable is writable by the current identity.",
                        directoryPath,
                        "Service",
                        principal,
                        state));
                }
            }
        }
        catch (Exception ex)
        {
            AddWarning($"Service scan failed: {ex.Message}");
        }
    }

    private void ScanScheduledTasks()
    {
        string tasksRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "Tasks");
        if (!Directory.Exists(tasksRoot))
        {
            AddWarning("Task Scheduler root directory was not found.");
            return;
        }

        foreach (string taskFile in EnumerateAccessibleFiles(tasksRoot))
        {
            try
            {
                XDocument document = XDocument.Load(taskFile, LoadOptions.None);
                XNamespace ns = document.Root?.Name.Namespace ?? XNamespace.None;

                List<(string Command, string Arguments)> actions = document
                    .Descendants(ns + "Exec")
                    .Select(exec => (
                        Command: exec.Element(ns + "Command")?.Value?.Trim() ?? string.Empty,
                        Arguments: exec.Element(ns + "Arguments")?.Value?.Trim() ?? string.Empty))
                    .Where(action => !string.IsNullOrWhiteSpace(action.Command))
                    .ToList();

                if (actions.Count == 0)
                {
                    continue;
                }

                XElement? principalNode = document.Descendants(ns + "Principal").FirstOrDefault();
                string principal = principalNode?.Element(ns + "UserId")?.Value?.Trim()
                    ?? principalNode?.Element(ns + "GroupId")?.Value?.Trim()
                    ?? "Unknown";

                string runLevel = principalNode?.Element(ns + "RunLevel")?.Value?.Trim() ?? "Unknown";
                bool privileged = WindowsSecurityHelper.IsPrivilegedPrincipal(principal);

                if (!privileged)
                {
                    continue;
                }

                string relativeTaskPath = taskFile[tasksRoot.Length..].TrimStart(Path.DirectorySeparatorChar);
                string target = $"\\{relativeTaskPath}";

                foreach ((string command, string arguments) in actions)
                {
                    string commandLine = string.IsNullOrWhiteSpace(arguments)
                        ? command
                        : $"{command} {arguments}";

                    string normalizedCommand = WindowsPathHelper.NormalizePath(command);

                    if (WindowsPathHelper.IsUnquotedExecutablePath(commandLine))
                    {
                        AddFinding(new VulnerabilityFinding(
                            "Unquoted Scheduled Task Path",
                            target,
                            Severity.High,
                            "A privileged scheduled task references an executable path with spaces that is not quoted.",
                            commandLine,
                            "ScheduledTask",
                            $"{principal} ({runLevel})"));
                    }

                    if (File.Exists(normalizedCommand) &&
                        WindowsSecurityHelper.IsFileWritableByCurrentIdentity(normalizedCommand))
                    {
                        AddFinding(new VulnerabilityFinding(
                            "Writable Scheduled Task Binary",
                            target,
                            Severity.Critical,
                            "A privileged scheduled task points to an executable writable by the current identity.",
                            normalizedCommand,
                            "ScheduledTask",
                            $"{principal} ({runLevel})"));
                    }

                    string? directoryPath = Path.GetDirectoryName(normalizedCommand);
                    if (!string.IsNullOrWhiteSpace(directoryPath) &&
                        Directory.Exists(directoryPath) &&
                        WindowsSecurityHelper.IsDirectoryWritableByCurrentIdentity(directoryPath))
                    {
                        AddFinding(new VulnerabilityFinding(
                            "Writable Scheduled Task Directory",
                            target,
                            Severity.High,
                            "A privileged scheduled task executable is stored in a writable directory.",
                            directoryPath,
                            "ScheduledTask",
                            $"{principal} ({runLevel})"));
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                AddWarning($"Access denied while reading task definition '{taskFile}'.");
            }
            catch (Exception ex)
            {
                AddWarning($"Task scan issue for '{taskFile}': {ex.Message}");
            }
        }
    }

    private void ScanRegistryKeys()
    {
        string[] criticalPaths = new string[]
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SYSTEM\CurrentControlSet\Services"
        };

        foreach (string subKey in criticalPaths)
        {
            try
            {
                using RegistryKey? key = Registry.LocalMachine.OpenSubKey(subKey, RegistryRights.ReadKey);
                if (key is null)
                {
                    continue;
                }

                if (!WindowsSecurityHelper.IsRegistryKeyWritableByCurrentIdentity(key))
                {
                    continue;
                }

                AddFinding(new VulnerabilityFinding(
                    "Writable Registry Key",
                    $@"HKLM\{subKey}",
                    Severity.High,
                    "The current identity can modify a sensitive machine-wide registry location.",
                    $@"HKLM\{subKey}",
                    "Registry"));
            }
            catch (Exception ex)
            {
                AddWarning($"Registry scan issue for HKLM\\{subKey}: {ex.Message}");
            }
        }
    }

    private void AddFinding(VulnerabilityFinding finding)
    {
        string dedupeKey = string.Join("|", finding.Type, finding.Target, finding.EvidencePath);
        if (_dedupeKeys.Add(dedupeKey))
        {
            _findings.Add(finding);
        }
    }

    private IEnumerable<string> EnumerateAccessibleFiles(string rootDirectory)
    {
        var pendingDirectories = new Stack<string>();
        pendingDirectories.Push(rootDirectory);

        while (pendingDirectories.Count > 0)
        {
            string currentDirectory = pendingDirectories.Pop();

            string[] files;
            try
            {
                files = Directory.GetFiles(currentDirectory);
            }
            catch (Exception ex)
            {
                AddWarning($"Unable to list files in '{currentDirectory}': {ex.Message}");
                continue;
            }

            foreach (string file in files)
            {
                yield return file;
            }

            string[] subDirectories;
            try
            {
                subDirectories = Directory.GetDirectories(currentDirectory);
            }
            catch (Exception ex)
            {
                AddWarning($"Unable to list directories in '{currentDirectory}': {ex.Message}");
                continue;
            }

            foreach (string subDirectory in subDirectories)
            {
                pendingDirectories.Push(subDirectory);
            }
        }
    }

    private void AddWarning(string message)
    {
        _warnings.Add(message);
        Log(message);
    }

    private void Log(string message)
    {
        if (_options.Verbose)
        {
            Console.WriteLine($"[*] {message}");
        }
    }

    private static IReadOnlyList<string> GetIPv4Addresses()
    {
        var addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            foreach (IPAddress address in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    addresses.Add(address.ToString());
                }
            }
        }
        catch
        {
            addresses.Add("Unavailable");
        }

        return addresses.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static int? TryConvertInt(object? value)
    {
        return value switch
        {
            null => null,
            int intValue => intValue,
            uint uintValue => checked((int)uintValue),
            ushort ushortValue => ushortValue,
            _ when int.TryParse(value.ToString(), out int parsed) => parsed,
            _ => null
        };
    }
}

[SupportedOSPlatform("windows")]
internal static class WindowsPathHelper
{
    private static readonly Regex ExecutableRegex = new(
        @"^(?<path>.+?\.(exe|com|bat|cmd|ps1|vbs|js|msc))(?=\s|$)",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    public static string NormalizePath(string path)
    {
        string cleaned = Environment.ExpandEnvironmentVariables(path.Trim().Trim('"'));

        if (cleaned.StartsWith(@"\??\", StringComparison.OrdinalIgnoreCase))
        {
            cleaned = cleaned[4..];
        }

        if (!Path.IsPathRooted(cleaned))
        {
            string candidate = Path.Combine(Environment.SystemDirectory, cleaned);
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return cleaned;
    }

    public static string? ExtractExecutablePath(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return null;
        }

        string trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            int endQuote = trimmed.IndexOf('"', 1);
            if (endQuote > 1)
            {
                return trimmed[1..endQuote];
            }
        }

        Match match = ExecutableRegex.Match(trimmed);
        if (match.Success)
        {
            return match.Groups["path"].Value;
        }

        string firstToken = trimmed.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries)[0];
        return firstToken;
    }

    public static bool IsUnquotedExecutablePath(string commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine))
        {
            return false;
        }

        string trimmed = commandLine.Trim();
        if (trimmed.StartsWith('"'))
        {
            return false;
        }

        string? executablePath = ExtractExecutablePath(trimmed);
        return !string.IsNullOrWhiteSpace(executablePath) && executablePath.Contains(' ');
    }
}

[SupportedOSPlatform("windows")]
internal static class WindowsSecurityHelper
{
    public static bool IsPrivilegedPrincipal(string principal)
    {
        if (string.IsNullOrWhiteSpace(principal))
        {
            return false;
        }

        string normalized = principal.Trim();
        return normalized.Equals("LocalSystem", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("S-1-5-18", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(@"NT AUTHORITY\LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("LocalService", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("S-1-5-19", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals(@"NT AUTHORITY\NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("NetworkService", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("S-1-5-20", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("Administrators", StringComparison.OrdinalIgnoreCase) ||
               normalized.Equals("S-1-5-32-544", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsFileWritableByCurrentIdentity(string filePath)
    {
        try
        {
            var fileInfo = new FileInfo(filePath);
            FileSecurity security = fileInfo.GetAccessControl();
            return WindowsEffectiveAccess.HasFileWriteAccess(security);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsDirectoryWritableByCurrentIdentity(string directoryPath)
    {
        try
        {
            var directoryInfo = new DirectoryInfo(directoryPath);
            DirectorySecurity security = directoryInfo.GetAccessControl();
            return WindowsEffectiveAccess.HasDirectoryWriteAccess(security);
        }
        catch
        {
            return false;
        }
    }

    public static bool IsRegistryKeyWritableByCurrentIdentity(RegistryKey key)
    {
        try
        {
            RegistrySecurity security = key.GetAccessControl();
            return WindowsEffectiveAccess.HasRegistryWriteAccess(security);
        }
        catch
        {
            return false;
        }
    }
}
