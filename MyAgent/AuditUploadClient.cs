using System.Net.Http;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;

[SupportedOSPlatform("windows")]
internal static class AuditUploadClient
{
    private static readonly JsonSerializerOptions PayloadOptions = new()
    {
        WriteIndented = false
    };

    public static void UploadIfConfigured(AuditReport report, AuditOptions options)
    {
        if (!options.UploadEnabled)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(options.ServerUrl) || string.IsNullOrWhiteSpace(options.ListenerId))
        {
            throw new InvalidOperationException("Both server URL and listener ID are required for upload.");
        }

        Uri serverUri = ValidateServerUri(options.ServerUrl);
        string reportJson = ReportWriter.SerializeJson(report);
        string agentId = ResolveAgentId(options, report);
        string filename = $"audit_{report.Timestamp:yyyy-MM-dd_HHmmss}.json";

        string? primaryIp = report.System.IPv4Addresses.Count > 0
            ? report.System.IPv4Addresses[0]
            : null;

        var payload = new
        {
            agent_id = agentId,
            machine_name = report.System.MachineName,
            hostname = report.System.MachineName,
            username = report.System.UserName,
            domain = report.System.Domain,
            operating_system = report.System.OsVersion,
            privileges = report.System.IsAdministrator ? "administrator" : "user",
            process_id = Environment.ProcessId,
            ip_address = primaryIp,
            architecture = RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(),
            agent_version = "myagent-audit-1.0",
            filename,
            report_json = reportJson,
            metadata = new
            {
                source = "myagent",
                finding_count = report.Findings.Count,
                risk_level = report.RiskLevel,
                uploaded_at = report.Timestamp,
            }
        };

        using var client = new HttpClient
        {
            BaseAddress = serverUri,
            Timeout = TimeSpan.FromSeconds(options.UploadTimeoutSeconds)
        };

        using var content = new StringContent(
            JsonSerializer.Serialize(payload, PayloadOptions),
            Encoding.UTF8,
            "application/json");

        string endpoint = $"/api/listeners/{Uri.EscapeDataString(options.ListenerId)}/audit-reports";
        using HttpResponseMessage response = client.PostAsync(endpoint, content).GetAwaiter().GetResult();
        string responseBody = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"HTTP upload failed with status {(int)response.StatusCode}: {responseBody}");
        }

        Console.WriteLine($"[+] JSON report uploaded to listener '{options.ListenerId}'.");
    }

    private static Uri ValidateServerUri(string serverUrl)
    {
        if (!Uri.TryCreate(serverUrl, UriKind.Absolute, out Uri? uri))
        {
            throw new InvalidOperationException("Upload server URL is invalid.");
        }

        if (uri.Scheme is not ("http" or "https"))
        {
            throw new InvalidOperationException("Upload server URL must use http or https.");
        }

        return new Uri($"{uri.Scheme}://{uri.Authority}");
    }

    private static string ResolveAgentId(AuditOptions options, AuditReport report)
    {
        if (!string.IsNullOrWhiteSpace(options.AgentId))
        {
            return SanitizeId(options.AgentId);
        }

        return SanitizeId($"audit_{report.System.MachineName}_{report.System.UserName}");
    }

    private static string SanitizeId(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (char character in value.Trim())
        {
            builder.Append(char.IsLetterOrDigit(character) || character is '-' or '_' ? character : '_');
        }

        return builder.Length > 0 ? builder.ToString() : "audit_agent";
    }
}
