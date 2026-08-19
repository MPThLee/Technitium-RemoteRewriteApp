using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

namespace RemoteRewrite;

internal sealed class SplitHorizonConfig
{
    const int MaxConfigFilePathLength = 1024;
    static readonly UTF8Encoding _strictUtf8 = new UTF8Encoding(false, true);

    public static readonly SplitHorizonConfig Disabled = new SplitHorizonConfig
    {
        Enable = false,
        DefaultGroupName = null,
        PrivateGroupName = null,
        PublicGroupName = null,
        ImportInstalledApp = false,
        ConfigFile = null,
        DomainGroupRules = Array.Empty<DomainGroupRule>(),
        NetworkGroupRules = Array.Empty<NetworkGroupRule>()
    };

    public bool Enable { get; private set; }
    public string DefaultGroupName { get; private set; }
    public string PrivateGroupName { get; private set; }
    public string PublicGroupName { get; private set; }
    public bool ImportInstalledApp { get; private set; }
    public string ConfigFile { get; private set; }
    public DomainGroupRule[] DomainGroupRules { get; private set; }
    public NetworkGroupRule[] NetworkGroupRules { get; private set; }

    public static SplitHorizonConfig Parse(JsonElement value)
    {
        RequireObject(value, "splitHorizon");
        EnsureUniqueProperties(value, "splitHorizon");

        int entryCount = 0;
        List<DomainGroupRule> domainRules = ParseDomainGroupMap(value, disabledGroups: null, ref entryCount);
        List<NetworkGroupRule> networkRules = ParseNetworkGroupMap(value, disabledGroups: null, ref entryCount);

        return new SplitHorizonConfig
        {
            Enable = GetBoolean(value, "enable", true),
            DefaultGroupName = GetGroupName(value, "defaultGroupName", "default"),
            PrivateGroupName = GetGroupName(value, "privateGroupName", "private"),
            PublicGroupName = GetGroupName(value, "publicGroupName", "public"),
            ImportInstalledApp = GetBoolean(value, "importInstalledApp", false),
            ConfigFile = GetConfigFile(value),
            DomainGroupRules = SortDomainRules(domainRules),
            NetworkGroupRules = SortNetworkRules(networkRules)
        };
    }

    public void LoadInstalledConfig(string applicationFolder)
    {
        LoadInstalledConfig(applicationFolder, beforeConfigOpen: null);
    }

    internal void LoadInstalledConfig(string applicationFolder, Action beforeConfigOpen)
    {
        if (!Enable || !ImportInstalledApp || string.IsNullOrWhiteSpace(applicationFolder))
            return;

        string applicationRoot = Directory.GetParent(Path.GetFullPath(applicationFolder))?.FullName;
        if (string.IsNullOrWhiteSpace(applicationRoot))
            return;

        string configFile = ConfigFile;
        if (string.IsNullOrWhiteSpace(configFile))
        {
            string officialPath = Path.Combine(applicationRoot, "Split Horizon", "dnsApp.config");
            string legacyPath = Path.Combine(applicationRoot, "SplitHorizonApp", "dnsApp.config");
            configFile = File.Exists(officialPath) ? officialPath : legacyPath;
        }
        else if (!Path.IsPathRooted(configFile))
        {
            configFile = Path.Combine(applicationFolder, configFile);
        }

        configFile = Path.GetFullPath(configFile);
        if (!IsPathWithin(applicationRoot, configFile))
            throw new FormatException("splitHorizon.configFile must remain within the DNS applications directory.");

        if (!File.Exists(configFile))
            return;

        string installedConfig;
        try
        {
            using FileStream stream = OpenValidatedConfigFile(applicationRoot, configFile, beforeConfigOpen);
            installedConfig = ReadStrictUtf8File(stream);
        }
        catch (DecoderFallbackException ex)
        {
            throw new FormatException("Split Horizon configuration must be valid UTF-8.", ex);
        }

        JsonDocument document;
        try
        {
            document = JsonDocument.Parse(installedConfig);
        }
        catch (JsonException ex)
        {
            throw new FormatException("Split Horizon configuration must contain valid JSON.", ex);
        }

        using (document)
        {
            JsonElement root = document.RootElement;
            RequireObject(root, "installed Split Horizon configuration");
            EnsureUniqueProperties(root, "installed Split Horizon configuration");

            HashSet<string> disabledGroups = ParseDisabledGroups(root);
            int importedEntryCount = 0;
            List<DomainGroupRule> domainRules = ParseDomainGroupMap(root, disabledGroups, ref importedEntryCount);
            List<NetworkGroupRule> networkRules = ParseNetworkGroupMap(root, disabledGroups, ref importedEntryCount);

            MergeImportedRules(domainRules, networkRules);
        }
    }

    public HashSet<string> ResolveGroups(string qname, IPAddress address)
    {
        HashSet<string> groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!Enable)
            return groups;

        AddGroup(groups, DefaultGroupName);
        AddGroup(groups, NetworkClassifier.IsPrivateOrSpecial(address) ? PrivateGroupName : PublicGroupName);

        DomainGroupRule domainRule = DomainGroupRules.FirstOrDefault(rule => rule.Matches(qname));
        if (domainRule is not null)
        {
            AddGroup(groups, domainRule.GroupName);
        }
        else
        {
            NetworkGroupRule networkRule = NetworkGroupRules.FirstOrDefault(rule => rule.Matches(address));
            if (networkRule is not null)
                AddGroup(groups, networkRule.GroupName);
        }

        return groups;
    }

    static void AddGroup(HashSet<string> groups, string name)
    {
        if (!string.IsNullOrWhiteSpace(name))
            groups.Add(name);
    }

    static string NormalizeGroupName(string value, string fieldName = "group name")
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException($"Split Horizon {fieldName} cannot be empty.");

        string normalized = value.Trim().ToLowerInvariant();
        if (normalized.Length > AppLimits.MaxGroupNameLength)
            throw new FormatException($"Split Horizon {fieldName} cannot exceed {AppLimits.MaxGroupNameLength} characters.");
        if (normalized.Any(char.IsControl))
            throw new FormatException($"Split Horizon {fieldName} cannot contain control characters.");

        return normalized;
    }

    internal static string NormalizeRuleGroupName(string value)
    {
        return NormalizeGroupName(value, "group name");
    }

    static HashSet<string> ParseDisabledGroups(JsonElement root)
    {
        HashSet<string> disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("groups", out JsonElement groups))
            return disabled;

        if (groups.ValueKind != JsonValueKind.Array)
            throw new FormatException("Installed Split Horizon groups must be a JSON array.");

        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        int count = 0;
        foreach (JsonElement group in groups.EnumerateArray())
        {
            if (++count > AppLimits.MaxSplitHorizonMapEntries)
                throw new FormatException($"Installed Split Horizon groups cannot exceed {AppLimits.MaxSplitHorizonMapEntries} entries.");

            RequireObject(group, "each installed Split Horizon group");
            EnsureUniqueProperties(group, "installed Split Horizon group");

            if (!group.TryGetProperty("name", out JsonElement nameElement) || nameElement.ValueKind != JsonValueKind.String)
                throw new FormatException("Each installed Split Horizon group must have a string name.");

            string name = NormalizeGroupName(nameElement.GetString(), "group name");
            if (!names.Add(name))
                throw new FormatException($"Duplicate installed Split Horizon group name after normalization: {name}");

            bool enabled = GetBoolean(group, "enabled", true);
            if (enabled)
                continue;

            disabled.Add(name);
        }

        return disabled;
    }

    static List<DomainGroupRule> ParseDomainGroupMap(
        JsonElement root,
        HashSet<string> disabledGroups,
        ref int entryCount)
    {
        List<DomainGroupRule> rules = new List<DomainGroupRule>();
        if (!root.TryGetProperty("domainGroupMap", out JsonElement map))
            return rules;

        RequireObject(map, "domainGroupMap");
        HashSet<string> patterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonProperty property in map.EnumerateObject())
        {
            IncrementMapEntryCount(ref entryCount);
            if (property.Value.ValueKind != JsonValueKind.String)
                throw new FormatException("Each domainGroupMap value must be a string group name.");

            DomainGroupRule rule = new DomainGroupRule(property.Name, property.Value.GetString());
            if (!patterns.Add(rule.Pattern))
                throw new FormatException($"Duplicate Split Horizon domain after normalization: {rule.Pattern}");
            if (disabledGroups is null || !disabledGroups.Contains(rule.GroupName))
                rules.Add(rule);
        }

        return rules;
    }

    static List<NetworkGroupRule> ParseNetworkGroupMap(
        JsonElement root,
        HashSet<string> disabledGroups,
        ref int entryCount)
    {
        List<NetworkGroupRule> rules = new List<NetworkGroupRule>();
        if (!root.TryGetProperty("networkGroupMap", out JsonElement map))
            return rules;

        RequireObject(map, "networkGroupMap");
        HashSet<string> patterns = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in map.EnumerateObject())
        {
            IncrementMapEntryCount(ref entryCount);
            if (property.Value.ValueKind != JsonValueKind.String)
                throw new FormatException("Each networkGroupMap value must be a string group name.");

            NetworkGroupRule rule = NetworkGroupRule.Parse(property.Name, property.Value.GetString());
            if (!patterns.Add(rule.CanonicalPattern))
                throw new FormatException($"Duplicate Split Horizon network after normalization: {rule.CanonicalPattern}");
            if (disabledGroups is null || !disabledGroups.Contains(rule.GroupName))
                rules.Add(rule);
        }

        return rules;
    }

    static void IncrementMapEntryCount(ref int entryCount)
    {
        if (++entryCount > AppLimits.MaxSplitHorizonMapEntries)
            throw new FormatException($"Split Horizon maps cannot exceed {AppLimits.MaxSplitHorizonMapEntries} total entries.");
    }

    void MergeImportedRules(IEnumerable<DomainGroupRule> domainRules, IEnumerable<NetworkGroupRule> networkRules)
    {
        List<DomainGroupRule> mergedDomains = DomainGroupRules.ToList();
        List<NetworkGroupRule> mergedNetworks = NetworkGroupRules.ToList();
        HashSet<string> domainPatterns = mergedDomains.Select(static rule => rule.Pattern).ToHashSet(StringComparer.OrdinalIgnoreCase);
        HashSet<string> networkPatterns = mergedNetworks.Select(static rule => rule.CanonicalPattern).ToHashSet(StringComparer.Ordinal);

        foreach (DomainGroupRule rule in domainRules)
        {
            // Explicit app mappings have deterministic precedence over imported mappings.
            if (!domainPatterns.Add(rule.Pattern))
                continue;
            EnsureMergedEntryCapacity(mergedDomains.Count + mergedNetworks.Count);
            mergedDomains.Add(rule);
        }

        foreach (NetworkGroupRule rule in networkRules)
        {
            if (!networkPatterns.Add(rule.CanonicalPattern))
                continue;
            EnsureMergedEntryCapacity(mergedDomains.Count + mergedNetworks.Count);
            mergedNetworks.Add(rule);
        }

        DomainGroupRules = SortDomainRules(mergedDomains);
        NetworkGroupRules = SortNetworkRules(mergedNetworks);
    }

    static void EnsureMergedEntryCapacity(int currentCount)
    {
        if (currentCount >= AppLimits.MaxSplitHorizonMapEntries)
            throw new FormatException($"Combined Split Horizon maps cannot exceed {AppLimits.MaxSplitHorizonMapEntries} entries.");
    }

    static DomainGroupRule[] SortDomainRules(IEnumerable<DomainGroupRule> rules)
    {
        return rules
            .OrderByDescending(static rule => rule.Pattern.Length)
            .ThenBy(static rule => rule.Pattern, StringComparer.Ordinal)
            .ToArray();
    }

    static NetworkGroupRule[] SortNetworkRules(IEnumerable<NetworkGroupRule> rules)
    {
        return rules
            .OrderByDescending(static rule => rule.PrefixLength)
            .ThenBy(static rule => rule.CanonicalPattern, StringComparer.Ordinal)
            .ToArray();
    }

    static bool GetBoolean(JsonElement root, string propertyName, bool defaultValue)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement value))
            return defaultValue;
        if (value.ValueKind != JsonValueKind.True && value.ValueKind != JsonValueKind.False)
            throw new FormatException($"splitHorizon.{propertyName} must be a JSON boolean.");
        return value.GetBoolean();
    }

    static string GetGroupName(JsonElement root, string propertyName, string defaultValue)
    {
        if (!root.TryGetProperty(propertyName, out JsonElement value))
            return defaultValue;
        if (value.ValueKind == JsonValueKind.Null)
            return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new FormatException($"splitHorizon.{propertyName} must be a string or null.");
        return NormalizeGroupName(value.GetString(), propertyName);
    }

    static string GetConfigFile(JsonElement root)
    {
        if (!root.TryGetProperty("configFile", out JsonElement value) || value.ValueKind == JsonValueKind.Null)
            return null;
        if (value.ValueKind != JsonValueKind.String)
            throw new FormatException("splitHorizon.configFile must be a string or null.");

        string path = value.GetString()?.Trim();
        if (string.IsNullOrEmpty(path))
            return null;
        if (path.Length > MaxConfigFilePathLength || path.Any(char.IsControl))
            throw new FormatException("splitHorizon.configFile is invalid or too long.");
        return path;
    }

    static void RequireObject(JsonElement value, string name)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new FormatException($"{name} must be a JSON object.");
    }

    static void EnsureUniqueProperties(JsonElement value, string name)
    {
        JsonObjectValidation.RequireUniqueProperties(value, name);
    }

    static bool IsPathWithin(string rootPath, string candidatePath)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath));
        string candidate = Path.GetFullPath(candidatePath);
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        if (candidate.Equals(root, comparison))
            return false;

        string prefix = Path.EndsInDirectorySeparator(root) ? root : root + Path.DirectorySeparatorChar;
        return candidate.StartsWith(prefix, comparison);
    }

    static FileStream OpenValidatedConfigFile(string applicationRoot, string configFile, Action beforeConfigOpen)
    {
        using SafeFileHandle rootHandle = OpenDirectoryHandle(applicationRoot);
        // The internal callback is a deterministic race-injection seam used by security tests.
        beforeConfigOpen?.Invoke();
        FileStream stream = new FileStream(
            configFile,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read | FileShare.Delete,
            4096,
            FileOptions.SequentialScan);

        try
        {
            // Validate the objects actually opened, then read from that same fixed file handle.
            // A path or symlink swap cannot redirect the subsequent read to another file.
            string resolvedRoot = ResolveHandlePath(rootHandle);
            string resolvedFile = ResolveHandlePath(stream.SafeFileHandle);
            if (!IsPathWithin(resolvedRoot, resolvedFile))
                throw new FormatException("splitHorizon.configFile resolves outside the DNS applications directory.");
            return stream;
        }
        catch
        {
            stream.Dispose();
            throw;
        }
    }

    static SafeFileHandle OpenDirectoryHandle(string path)
    {
        SafeFileHandle handle;
        if (OperatingSystem.IsWindows())
        {
            handle = CreateFile(
                path,
                0x80u, // FILE_READ_ATTRIBUTES
                0x00000001u | 0x00000002u | 0x00000004u, // FILE_SHARE_READ | WRITE | DELETE
                IntPtr.Zero,
                3u, // OPEN_EXISTING
                0x02000000u, // FILE_FLAG_BACKUP_SEMANTICS
                IntPtr.Zero);
        }
        else if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
        {
            int descriptor = Open(path, 0); // O_RDONLY; the handle is used only for canonical identity.
            if (descriptor < 0)
            {
                int error = Marshal.GetLastPInvokeError();
                throw new IOException($"Cannot securely open the DNS applications directory: {new Win32Exception(error).Message}");
            }
            handle = new SafeFileHandle(new IntPtr(descriptor), ownsHandle: true);
        }
        else
        {
            throw new PlatformNotSupportedException("Secure Split Horizon configuration import is not supported on this operating system.");
        }

        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw new IOException($"Cannot securely open the DNS applications directory: {new Win32Exception(error).Message}");
        }

        return handle;
    }

    static string ResolveHandlePath(SafeFileHandle handle)
    {
        if (OperatingSystem.IsWindows())
            return ResolveWindowsHandlePath(handle);
        if (OperatingSystem.IsLinux())
            return ResolveLinuxHandlePath(handle);
        if (OperatingSystem.IsMacOS())
            return ResolveMacHandlePath(handle);
        throw new PlatformNotSupportedException("Secure Split Horizon configuration import is not supported on this operating system.");
    }

    static string ResolveWindowsHandlePath(SafeFileHandle handle)
    {
        int capacity = 512;
        while (capacity <= 32768)
        {
            StringBuilder path = new StringBuilder(capacity);
            uint length = GetFinalPathNameByHandle(handle, path, (uint)path.Capacity, 0u);
            if (length == 0)
                throw CreateHandleResolutionException("Cannot resolve an imported Split Horizon configuration path");
            if (length < path.Capacity)
                return NormalizeWindowsHandlePath(path.ToString());
            capacity = checked((int)length + 1);
        }

        throw new FormatException("The resolved Split Horizon configuration path is too long.");
    }

    static string NormalizeWindowsHandlePath(string path)
    {
        const string uncPrefix = @"\\?\UNC\";
        const string extendedPrefix = @"\\?\";
        if (path.StartsWith(uncPrefix, StringComparison.OrdinalIgnoreCase))
            return @"\\" + path.Substring(uncPrefix.Length);
        if (path.StartsWith(extendedPrefix, StringComparison.Ordinal)
            && path.Length >= extendedPrefix.Length + 3
            && char.IsAsciiLetter(path[extendedPrefix.Length])
            && path[extendedPrefix.Length + 1] == ':')
        {
            return path.Substring(extendedPrefix.Length);
        }
        return path;
    }

    static string ResolveLinuxHandlePath(SafeFileHandle handle)
    {
        string descriptorPath = "/proc/self/fd/" + handle.DangerousGetHandle().ToInt64().ToString(CultureInfo.InvariantCulture);
        int capacity = 4096;
        while (capacity <= 65536)
        {
            byte[] bytes = new byte[capacity];
            nint length = ReadLink(descriptorPath, bytes, (nuint)bytes.Length);
            if (length < 0)
                throw CreateHandleResolutionException("Cannot resolve an imported Split Horizon configuration path");
            if ((long)length < bytes.Length)
            {
                string path = _strictUtf8.GetString(bytes, 0, checked((int)length));
                if (path.EndsWith(" (deleted)", StringComparison.Ordinal))
                    throw new FormatException("The imported Split Horizon configuration was removed while it was being opened.");
                return path;
            }

            capacity *= 2;
        }

        throw new FormatException("The resolved Split Horizon configuration path is too long.");
    }

    static string ResolveMacHandlePath(SafeFileHandle handle)
    {
        // proc_pidfdinfo is non-variadic; directly P/Invoking fcntl(F_GETPATH)
        // corrupts calls on the Darwin ARM64 variadic ABI.
        const int pathBufferLength = 4096;
        const int maximumPathLength = 1024;
        const int procPidFdVnodePathInfo = 2;
        IntPtr buffer = Marshal.AllocHGlobal(pathBufferLength);
        try
        {
            int bytesReturned = ProcPidFdInfo(
                Environment.ProcessId,
                handle.DangerousGetHandle().ToInt32(),
                procPidFdVnodePathInfo,
                buffer,
                pathBufferLength);
            if (bytesReturned <= maximumPathLength)
                throw CreateHandleResolutionException("Cannot resolve an imported Split Horizon configuration path");

            byte[] bytes = new byte[bytesReturned];
            Marshal.Copy(buffer, bytes, 0, bytes.Length);
            int pathOffset = bytesReturned - maximumPathLength;
            int pathEnd = Array.IndexOf(bytes, (byte)0, pathOffset);
            if (pathEnd < 0)
                throw new FormatException("The resolved Split Horizon configuration path is too long.");
            return _strictUtf8.GetString(bytes, pathOffset, pathEnd - pathOffset);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    static IOException CreateHandleResolutionException(string message)
    {
        int error = Marshal.GetLastPInvokeError();
        return new IOException($"{message}: {new Win32Exception(error).Message}");
    }

    static string ReadStrictUtf8File(FileStream stream)
    {
        if (stream.Length > AppLimits.MaxAppRecordBytes)
            throw new FormatException($"Split Horizon configuration exceeds the {AppLimits.MaxAppRecordBytes}-byte limit.");

        byte[] bytes = new byte[AppLimits.MaxAppRecordBytes + 1];
        int count = 0;
        while (count < bytes.Length)
        {
            int read = stream.Read(bytes, count, bytes.Length - count);
            if (read == 0)
                break;
            count += read;
        }

        if (count > AppLimits.MaxAppRecordBytes || stream.ReadByte() != -1)
            throw new FormatException($"Split Horizon configuration exceeds the {AppLimits.MaxAppRecordBytes}-byte limit.");
        return _strictUtf8.GetString(bytes, 0, count);
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateFileW")]
    static extern SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "GetFinalPathNameByHandleW")]
    static extern uint GetFinalPathNameByHandle(
        SafeFileHandle file,
        StringBuilder filePath,
        uint filePathLength,
        uint flags);

    [DllImport("libc", SetLastError = true, EntryPoint = "open")]
    static extern int Open(string path, int flags);

    [DllImport("libc", SetLastError = true, EntryPoint = "readlink")]
    static extern nint ReadLink(string path, byte[] buffer, nuint bufferSize);

    [DllImport("libc", SetLastError = true, EntryPoint = "proc_pidfdinfo")]
    static extern int ProcPidFdInfo(int processId, int descriptor, int flavor, IntPtr buffer, int bufferSize);
}

internal static class NetworkClassifier
{
    public static bool IsPrivateOrSpecial(IPAddress address)
    {
        if (address is null)
            return false;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address))
            return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && (bytes[1] >= 16) && (bytes[1] <= 31))
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || bytes[0] == 127;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.Equals(IPAddress.IPv6Loopback))
                return true;

            byte[] bytes = address.GetAddressBytes();
            return (bytes[0] & 0xFE) == 0xFC || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
        }

        return false;
    }
}

internal sealed class DomainGroupRule
{
    public DomainGroupRule(string pattern, string groupName)
    {
        Pattern = NormalizeDomain(pattern);
        GroupName = SplitHorizonConfig.NormalizeRuleGroupName(groupName);
    }

    public string Pattern { get; }
    public string GroupName { get; }

    public bool Matches(string qname)
    {
        if (string.IsNullOrWhiteSpace(qname))
            return false;

        string candidate = qname.TrimEnd('.');
        return candidate.Equals(Pattern, StringComparison.OrdinalIgnoreCase)
            || candidate.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);
    }

    static string NormalizeDomain(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            throw new FormatException("Split Horizon domain names cannot be empty.");

        string domain = value.Trim();
        if (domain.StartsWith(".", StringComparison.Ordinal))
            domain = domain.Substring(1);
        if (domain.EndsWith(".", StringComparison.Ordinal))
            domain = domain.Substring(0, domain.Length - 1);
        if (domain.Length == 0 || domain.Length > AppLimits.MaxDomainNameLength || domain.Contains("..", StringComparison.Ordinal))
            throw new FormatException($"Split Horizon domain names must be valid and no longer than {AppLimits.MaxDomainNameLength} characters.");

        IdnMapping idn = new IdnMapping();
        string[] labels = domain.Split('.');
        for (int index = 0; index < labels.Length; index++)
        {
            string label;
            try
            {
                label = idn.GetAscii(labels[index]).ToLowerInvariant();
            }
            catch (ArgumentException ex)
            {
                throw new FormatException($"Invalid Split Horizon domain name: {value}", ex);
            }

            if (label.Length == 0 || label.Length > 63
                || label[0] == '-' || label[label.Length - 1] == '-'
                || label.Any(static character => !(character >= 'a' && character <= 'z')
                    && !(character >= '0' && character <= '9')
                    && character != '-'))
            {
                throw new FormatException($"Invalid Split Horizon domain name: {value}");
            }

            labels[index] = label;
        }

        string normalized = string.Join('.', labels);
        if (normalized.Length > AppLimits.MaxDomainNameLength)
            throw new FormatException($"Split Horizon domain names cannot exceed {AppLimits.MaxDomainNameLength} characters after IDN normalization.");
        return normalized;
    }
}

internal sealed class NetworkGroupRule
{
    NetworkGroupRule(IPAddress network, int prefixLength, string groupName)
    {
        Network = network;
        PrefixLength = prefixLength;
        GroupName = SplitHorizonConfig.NormalizeRuleGroupName(groupName);
        CanonicalPattern = network + "/" + prefixLength.ToString(CultureInfo.InvariantCulture);
    }

    public IPAddress Network { get; }
    public int PrefixLength { get; }
    public string GroupName { get; }
    public string CanonicalPattern { get; }

    public static NetworkGroupRule Parse(string pattern, string groupName)
    {
        string trimmed = pattern?.Trim();
        if (string.IsNullOrEmpty(trimmed) || trimmed.Length > 128 || trimmed.Any(char.IsControl) || trimmed.Contains('%'))
            throw new FormatException("Split Horizon network patterns are invalid or too long.");

        string addressText = trimmed;
        int? requestedPrefix = null;
        if (trimmed.Contains('/'))
        {
            string[] parts = trimmed.Split('/', 2);
            addressText = parts[0];
            if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int parsedPrefix))
                throw new FormatException($"Invalid prefix length for network '{pattern}'.");
            requestedPrefix = parsedPrefix;
        }

        if (!IPAddress.TryParse(addressText, out IPAddress address)
            || (address.AddressFamily != AddressFamily.InterNetwork && address.AddressFamily != AddressFamily.InterNetworkV6)
            || address.IsIPv4MappedToIPv6
            || (address.AddressFamily == AddressFamily.InterNetworkV6 && address.ScopeId != 0))
        {
            throw new FormatException($"Invalid IP address in Split Horizon network '{pattern}'.");
        }

        int maximumPrefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        int prefixLength = requestedPrefix ?? maximumPrefixLength;
        if (prefixLength < 0 || prefixLength > maximumPrefixLength)
            throw new FormatException($"Invalid prefix length {prefixLength} for network '{pattern}'.");

        byte[] addressBytes = address.GetAddressBytes();
        byte[] networkBytes = MaskAddress(addressBytes, prefixLength);
        if (!addressBytes.SequenceEqual(networkBytes))
            throw new FormatException($"Split Horizon network '{pattern}' has host bits set; use the canonical network address.");

        return new NetworkGroupRule(new IPAddress(networkBytes), prefixLength, groupName);
    }

    public bool Matches(IPAddress address)
    {
        if (address is null)
            return false;

        IPAddress candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        IPAddress network = Network.IsIPv4MappedToIPv6 ? Network.MapToIPv4() : Network;

        if (candidate.AddressFamily != network.AddressFamily)
            return false;

        byte[] left = candidate.GetAddressBytes();
        byte[] right = network.GetAddressBytes();
        int remainingBits = PrefixLength;

        for (int i = 0; i < left.Length && remainingBits > 0; i++)
        {
            int bitsToCompare = Math.Min(8, remainingBits);
            int mask = 0xFF << (8 - bitsToCompare);

            if ((left[i] & mask) != (right[i] & mask))
                return false;

            remainingBits -= bitsToCompare;
        }

        return true;
    }

    static byte[] MaskAddress(byte[] address, int prefixLength)
    {
        byte[] result = (byte[])address.Clone();
        int fullBytes = prefixLength / 8;
        int partialBits = prefixLength % 8;

        if (partialBits != 0)
        {
            result[fullBytes] &= (byte)(0xFF << (8 - partialBits));
            fullBytes++;
        }

        Array.Clear(result, fullBytes, result.Length - fullBytes);
        return result;
    }
}
