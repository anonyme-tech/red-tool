using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

[SupportedOSPlatform("windows")]
internal static class ReportWriter
{
    public static void Write(AuditReport report, AuditOptions options)
    {
        switch (options.Format)
        {
            case OutputFormat.Json:
                WriteJson(report, options);
                break;
            case OutputFormat.Csv:
                WriteCsv(report, options);
                break;
            default:
                WriteConsole(report);
                break;
        }
    }

    public static string SerializeJson(AuditReport report)
    {
        string json = JsonSerializer.Serialize(CreateJsonPayload(report), new JsonSerializerOptions
        {
            WriteIndented = true
        });
        return json;
    }

    private static void WriteConsole(AuditReport report)
    {
        Console.WriteLine("=== WINDOWS SECURITY AUDIT REPORT ===");
        Console.WriteLine();
        Console.WriteLine($"Timestamp     : {report.Timestamp:yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine($"Machine       : {report.System.MachineName}");
        Console.WriteLine($"User          : {report.System.Domain}\\{report.System.UserName}");
        Console.WriteLine($"OS            : {report.System.OsVersion}");
        Console.WriteLine($"Administrator : {report.System.IsAdministrator}");
        Console.WriteLine($"IPv4          : {string.Join(", ", report.System.IPv4Addresses)}");

        if (!string.IsNullOrWhiteSpace(report.System.CpuName))
        {
            Console.WriteLine($"CPU           : {report.System.CpuName} ({report.System.CpuCoreCount?.ToString() ?? "?"} cores)");
        }

        if (report.System.TotalMemoryMb.HasValue)
        {
            Console.WriteLine($"RAM           : {report.System.TotalMemoryMb.Value} MB");
        }

        Console.WriteLine();
        Console.WriteLine($"Findings      : {report.Findings.Count}");
        Console.WriteLine($"Risk Level    : {report.RiskLevel}");

        if (report.Findings.Count == 0)
        {
            Console.WriteLine();
            Console.WriteLine("[+] No security findings detected.");
        }
        else
        {
            foreach (IGrouping<Severity, VulnerabilityFinding> group in report.Findings.GroupBy(item => item.Severity))
            {
                Console.WriteLine();
                Console.WriteLine($"{group.Key.ToDisplayString()} ({group.Count()})");
                Console.WriteLine(new string('-', 72));

                foreach (VulnerabilityFinding finding in group)
                {
                    Console.WriteLine($"[{finding.Category}] {finding.Type}");
                    Console.WriteLine($"Target      : {finding.Target}");
                    Console.WriteLine($"Description : {finding.Description}");
                    Console.WriteLine($"Evidence    : {finding.EvidencePath}");

                    if (!string.IsNullOrWhiteSpace(finding.Principal))
                    {
                        Console.WriteLine($"Principal   : {finding.Principal}");
                    }

                    if (!string.IsNullOrWhiteSpace(finding.State))
                    {
                        Console.WriteLine($"State       : {finding.State}");
                    }

                    Console.WriteLine();
                }
            }
        }

        if (report.Warnings.Count > 0)
        {
            Console.WriteLine("Warnings");
            Console.WriteLine(new string('-', 72));

            foreach (string warning in report.Warnings)
            {
                Console.WriteLine($"[!] {warning}");
            }
        }
    }

    private static void WriteJson(AuditReport report, AuditOptions options)
    {
        string outputPath = ResolveOutputPath(options, "json");
        string json = SerializeJson(report);

        File.WriteAllText(outputPath, json, Encoding.UTF8);
        Console.WriteLine($"[+] JSON report written to: {outputPath}");
    }

    private static void WriteCsv(AuditReport report, AuditOptions options)
    {
        string outputPath = ResolveOutputPath(options, "csv");
        var builder = new StringBuilder();
        builder.AppendLine("Severity,Category,Type,Target,Description,EvidencePath,Principal,State");

        foreach (VulnerabilityFinding finding in report.Findings)
        {
            builder
                .Append(EscapeCsv(finding.Severity.ToCsvString())).Append(',')
                .Append(EscapeCsv(finding.Category)).Append(',')
                .Append(EscapeCsv(finding.Type)).Append(',')
                .Append(EscapeCsv(finding.Target)).Append(',')
                .Append(EscapeCsv(finding.Description)).Append(',')
                .Append(EscapeCsv(finding.EvidencePath)).Append(',')
                .Append(EscapeCsv(finding.Principal ?? string.Empty)).Append(',')
                .Append(EscapeCsv(finding.State ?? string.Empty))
                .AppendLine();
        }

        File.WriteAllText(outputPath, builder.ToString(), Encoding.UTF8);
        Console.WriteLine($"[+] CSV report written to: {outputPath}");
    }

    private static string ResolveOutputPath(AuditOptions options, string extension)
    {
        if (!string.IsNullOrWhiteSpace(options.OutputPath))
        {
            string fullPath = Path.GetFullPath(options.OutputPath);
            string? directory = Path.GetDirectoryName(fullPath);

            if (!string.IsNullOrWhiteSpace(directory))
            {
                Directory.CreateDirectory(directory);
            }

            return fullPath;
        }

        string fileName = $"audit_{DateTime.Now:yyyy-MM-dd_HHmmss}.{extension}";
        return Path.Combine(Environment.CurrentDirectory, fileName);
    }

    private static string EscapeCsv(string value)
    {
        string escaped = value.Replace("\"", "\"\"");
        return $"\"{escaped}\"";
    }

    private static object CreateJsonPayload(AuditReport report) =>
        new
        {
            timestamp = report.Timestamp,
            system = report.System,
            riskLevel = report.RiskLevel,
            findingCount = report.Findings.Count,
            findings = report.Findings.Select(finding => new
            {
                type = finding.Type,
                target = finding.Target,
                severity = finding.Severity.ToDisplayString(),
                category = finding.Category,
                description = finding.Description,
                evidencePath = finding.EvidencePath,
                principal = finding.Principal,
                state = finding.State
            }),
            warnings = report.Warnings
        };
}
