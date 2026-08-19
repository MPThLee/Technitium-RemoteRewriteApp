using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace RemoteRewrite;

internal sealed class AppRecordOptions
{
    const int MaxGroupNames = 64;
    const int MaxGroupNameLength = 128;

    static readonly AppRecordOptions Empty = new AppRecordOptions
    {
        Enable = true,
        SourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        GroupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        OverrideTtl = null,
        InlineRules = Array.Empty<RewriteRule>(),
        SplitHorizonScopes = Array.Empty<SplitHorizonScope>()
    };
    static readonly ConcurrentDictionary<string, Lazy<ParseResult>> _cache = new ConcurrentDictionary<string, Lazy<ParseResult>>(StringComparer.Ordinal);
    static readonly object _cacheGate = new object();

    public bool Enable { get; private set; }
    public HashSet<string> SourceNames { get; private set; }
    public HashSet<string> GroupNames { get; private set; }
    public uint? OverrideTtl { get; private set; }
    public RewriteRule[] InlineRules { get; private set; }
    public SplitHorizonScope[] SplitHorizonScopes { get; private set; }

    public static AppRecordOptions Parse(string appRecordData)
    {
        if (string.IsNullOrWhiteSpace(appRecordData))
            return Empty;

        ParseResult result = GetParseResult(appRecordData);
        if (result.Options is null)
            throw new FormatException(result.Error);

        return result.Options;
    }

    public static bool TryParse(string appRecordData, out AppRecordOptions options)
    {
        if (string.IsNullOrWhiteSpace(appRecordData))
        {
            options = Empty;
            return true;
        }

        ParseResult result = GetParseResult(appRecordData);
        options = result.Options;
        return options is not null;
    }

    public static void ClearCache()
    {
        lock (_cacheGate)
            _cache.Clear();
    }

    internal static int CacheEntryCount => _cache.Count;

    public AppRecordEffectiveOptions Resolve(
        HashSet<string> resolvedGroups,
        string defaultGroupName = "default",
        string privateGroupName = "private",
        string publicGroupName = "public")
    {
        SplitHorizonScope[] matchingScopes = SplitHorizonScopes
            .Where(scope => resolvedGroups.Contains(scope.GroupName))
            .ToArray();

        if (matchingScopes.Length == 0)
            return new AppRecordEffectiveOptions(Enable, SourceNames, GroupNames, OverrideTtl, InlineRules);

        int highestPriority = matchingScopes.Max(scope => GetScopePriority(scope.GroupName, defaultGroupName, privateGroupName, publicGroupName));
        SplitHorizonScope[] mostSpecificScopes = matchingScopes
            .Where(scope => GetScopePriority(scope.GroupName, defaultGroupName, privateGroupName, publicGroupName) == highestPriority)
            .ToArray();

        // A client must never get an arbitrary policy merely because JSON property order changed.
        if (mostSpecificScopes.Length != 1)
            return AppRecordEffectiveOptions.ResolutionFailure;

        SplitHorizonScope selected = mostSpecificScopes[0];
        return new AppRecordEffectiveOptions(
            selected.Enable ?? Enable,
            selected.SourceNames ?? SourceNames,
            selected.GroupNames ?? GroupNames,
            selected.OverrideTtlSpecified ? selected.OverrideTtl : OverrideTtl,
            selected.InlineRules ?? InlineRules
        );
    }

    static int GetScopePriority(string groupName, string defaultGroupName, string privateGroupName, string publicGroupName)
    {
        if (GroupNameEquals(groupName, privateGroupName) || GroupNameEquals(groupName, publicGroupName))
            return 1;
        if (GroupNameEquals(groupName, defaultGroupName))
            return 0;

        // A domain/network-mapped custom group is more specific than the built-in client
        // classification, which in turn is more specific than the default group.
        return 2;
    }

    static bool GroupNameEquals(string left, string right)
    {
        return !string.IsNullOrWhiteSpace(right) && left.Equals(right.Trim(), StringComparison.OrdinalIgnoreCase);
    }

    public bool MatchesGroups(HashSet<string> resolvedGroups)
    {
        AppRecordEffectiveOptions effective = Resolve(resolvedGroups);
        return !effective.ResolutionFailed && effective.MatchesGroups(resolvedGroups);
    }

    static AppRecordOptions ParseCore(string appRecordData)
    {
        using JsonDocument document = JsonDocument.Parse(appRecordData);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("APP-record configuration must be a JSON object.");
        JsonObjectValidation.RequireUniqueProperties(root, "APP-record configuration");

        int inlineOrder = 0;
        int inlineSourceCount = 0;
        RuleParseBudget budget = new RuleParseBudget(
            AppLimits.MaxAppRecordRules,
            AppLimits.MaxAppRecordRegexRules,
            AppLimits.MaxAppRecordAnswerMemberships,
            AppLimits.MaxAppRecordGroupIndexMemberships,
            AppLimits.MaxAppRecordQueryTypeMemberships);

        return new AppRecordOptions
        {
            Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            SourceNames = root.TryGetProperty("sourceNames", out JsonElement sourceNames)
                ? ParseStringArray(sourceNames)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            GroupNames = root.TryGetProperty("groupNames", out JsonElement groupNames)
                ? ParseStringArray(groupNames)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            OverrideTtl = ParseOptionalTtl(root, "overrideTtl"),
            InlineRules = ParseInlineRules(root, "inlineSources", "__apprecord_inline", ref inlineOrder, ref inlineSourceCount, budget),
            SplitHorizonScopes = ParseSplitHorizonMap(root, ref inlineOrder, ref inlineSourceCount, budget)
        };
    }

    static RewriteRule[] ParseInlineRules(
        JsonElement item,
        string propertyName,
        string sourcePrefix,
        ref int order,
        ref int sourceCount,
        RuleParseBudget budget)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement inlineSources))
            return Array.Empty<RewriteRule>();

        if (inlineSources.ValueKind != JsonValueKind.Array)
            throw new FormatException($"APP-record property '{propertyName}' must be an array.");

        List<RewriteRule> rules = new List<RewriteRule>();
        int index = 0;

        foreach (JsonElement inlineSource in inlineSources.EnumerateArray())
        {
            sourceCount++;
            if (sourceCount > AppLimits.MaxSources)
                throw new FormatException($"APP-record configuration cannot contain more than {AppLimits.MaxSources} inline sources.");

            SourceConfig source = SourceConfig.Parse(inlineSource, $"{sourcePrefix}_{index++}");
            if (!source.Enable)
                continue;

            if (string.IsNullOrWhiteSpace(source.Text) || !string.IsNullOrWhiteSpace(source.Url))
                throw new FormatException("APP-record inline sources must contain text and cannot contain a URL.");

            int ruleCountBeforeSource = budget.RuleCount;

            switch (source.Format)
            {
                case SourceFormat.AdGuardFilter:
                    rules.AddRange(RuleParser.ParseAdGuardFilterSource(source, source.Text, ref order, budget));
                    break;

                case SourceFormat.RewriteRulesJson:
                    rules.AddRange(RuleParser.ParseRewriteRulesJsonSource(source, source.Text, ref order, budget));
                    break;
            }

            if (budget.RuleCount == ruleCountBeforeSource)
                throw new FormatException($"APP-record inline source '{source.Name}' produced no valid rules.");
        }

        return rules.ToArray();
    }

    static SplitHorizonScope[] ParseSplitHorizonMap(JsonElement root, ref int order, ref int sourceCount, RuleParseBudget budget)
    {
        if (!root.TryGetProperty("splitHorizonMap", out JsonElement splitHorizonMap))
            return Array.Empty<SplitHorizonScope>();

        if (splitHorizonMap.ValueKind != JsonValueKind.Object)
            throw new FormatException("APP-record property 'splitHorizonMap' must be an object.");

        List<SplitHorizonScope> scopes = new List<SplitHorizonScope>();
        HashSet<string> seenGroupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (JsonProperty property in splitHorizonMap.EnumerateObject())
        {
            if (scopes.Count >= AppLimits.MaxSplitHorizonScopes)
                throw new FormatException($"APP-record configuration cannot contain more than {AppLimits.MaxSplitHorizonScopes} split-horizon scopes.");
            if (string.IsNullOrWhiteSpace(property.Name) || property.Value.ValueKind != JsonValueKind.Object)
                throw new FormatException("Each APP-record split-horizon scope must have a non-empty name and object value.");

            string groupName = property.Name.Trim().ToLowerInvariant();
            if (groupName.Length > MaxGroupNameLength)
                throw new FormatException($"APP-record group names cannot exceed {MaxGroupNameLength} characters.");
            if (!seenGroupNames.Add(groupName))
                throw new FormatException($"APP-record split-horizon scope '{groupName}' is duplicated after normalization.");

            JsonElement value = property.Value;
            JsonObjectValidation.RequireUniqueProperties(value, $"APP-record split-horizon scope '{groupName}'");
            HashSet<string> scopedSourceNames = ParseOptionalStringArray(value, "sourceNames");
            HashSet<string> scopedGroupNames = ParseOptionalStringArray(value, "groupNames");
            RewriteRule[] scopedInlineRules = ParseOptionalInlineRules(
                value,
                "inlineSources",
                $"__split_{property.Name}",
                ref order,
                ref sourceCount,
                budget);
            bool overrideTtlSpecified = value.TryGetProperty("overrideTtl", out _);

            scopes.Add(new SplitHorizonScope
            {
                GroupName = groupName,
                Enable = value.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : null,
                SourceNames = scopedSourceNames,
                GroupNames = scopedGroupNames,
                OverrideTtl = ParseOptionalTtl(value, "overrideTtl"),
                OverrideTtlSpecified = overrideTtlSpecified,
                InlineRules = scopedInlineRules
            });
        }

        return scopes.ToArray();
    }

    static HashSet<string> ParseOptionalStringArray(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement value))
            return null;
        if (value.ValueKind == JsonValueKind.Null)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        return ParseStringArray(value);
    }

    static RewriteRule[] ParseOptionalInlineRules(
        JsonElement item,
        string propertyName,
        string sourcePrefix,
        ref int order,
        ref int sourceCount,
        RuleParseBudget budget)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement value))
            return null;
        if (value.ValueKind == JsonValueKind.Null)
            return Array.Empty<RewriteRule>();

        return ParseInlineRules(item, propertyName, sourcePrefix, ref order, ref sourceCount, budget);
    }

    static HashSet<string> ParseStringArray(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array)
            throw new FormatException("APP-record sourceNames and groupNames must be arrays.");

        HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement entry in value.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(entry.GetString()))
                throw new FormatException("APP-record sourceNames and groupNames must contain only non-empty strings.");

            string normalized = entry.GetString().Trim().ToLowerInvariant();
            if (normalized.Length > MaxGroupNameLength)
                throw new FormatException($"APP-record source and group names cannot exceed {MaxGroupNameLength} characters.");

            result.Add(normalized);
            if (result.Count > MaxGroupNames)
                throw new FormatException($"APP-record sourceNames and groupNames cannot contain more than {MaxGroupNames} distinct entries.");
        }

        return result;
    }

    static uint? ParseOptionalTtl(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement ttl) || ttl.ValueKind == JsonValueKind.Null)
            return null;
        if (ttl.ValueKind != JsonValueKind.Number || !ttl.TryGetUInt32(out uint value))
            throw new FormatException($"APP-record property '{propertyName}' must be a non-negative integer or null.");
        if (value > AppLimits.MaximumTtl)
            throw new FormatException($"APP-record property '{propertyName}' cannot exceed {AppLimits.MaximumTtl} seconds.");
        return value;
    }

    static ParseResult GetParseResult(string appRecordData)
    {
        if (Encoding.UTF8.GetByteCount(appRecordData) > AppLimits.MaxAppRecordBytes)
            return ParseResult.Invalid($"APP-record configuration exceeds the {AppLimits.MaxAppRecordBytes}-byte limit.");

        if (_cache.TryGetValue(appRecordData, out Lazy<ParseResult> cached))
            return cached.Value;

        Lazy<ParseResult> admitted;
        lock (_cacheGate)
        {
            if (_cache.TryGetValue(appRecordData, out cached))
                return cached.Value;

            while (_cache.Count >= AppLimits.MaxAppRecordCacheEntries)
            {
                string evictionKey = _cache.Keys.FirstOrDefault();
                if (evictionKey is null || !_cache.TryRemove(evictionKey, out _))
                    break;
            }

            admitted = new Lazy<ParseResult>(() => ParseSafely(appRecordData), LazyThreadSafetyMode.ExecutionAndPublication);
            _cache[appRecordData] = admitted;
        }

        return admitted.Value;
    }

    static ParseResult ParseSafely(string appRecordData)
    {
        try
        {
            return ParseResult.Valid(ParseCore(appRecordData));
        }
        catch (Exception ex) when (ex is JsonException or FormatException or InvalidOperationException or NotSupportedException or ArgumentException or OverflowException or KeyNotFoundException)
        {
            return ParseResult.Invalid("Invalid APP-record configuration: " + ex.Message);
        }
    }

    sealed class ParseResult
    {
        ParseResult(AppRecordOptions options, string error)
        {
            Options = options;
            Error = error;
        }

        public AppRecordOptions Options { get; }
        public string Error { get; }
        public static ParseResult Valid(AppRecordOptions options) => new ParseResult(options, null);
        public static ParseResult Invalid(string error) => new ParseResult(null, error);
    }
}

internal sealed class AppRecordEffectiveOptions
{
    public static readonly AppRecordEffectiveOptions ResolutionFailure = new AppRecordEffectiveOptions(
        false,
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        null,
        Array.Empty<RewriteRule>(),
        resolutionFailed: true
    );

    public static readonly AppRecordEffectiveOptions GlobalDefault = new AppRecordEffectiveOptions(
        true,
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        null,
        Array.Empty<RewriteRule>()
    );

    public AppRecordEffectiveOptions(
        bool enable,
        HashSet<string> sourceNames,
        HashSet<string> groupNames,
        uint? overrideTtl,
        RewriteRule[] inlineRules,
        bool resolutionFailed = false)
    {
        Enable = enable;
        SourceNames = sourceNames;
        GroupNames = groupNames;
        OverrideTtl = overrideTtl;
        InlineRules = inlineRules;
        ResolutionFailed = resolutionFailed;
    }

    public bool Enable { get; }
    public HashSet<string> SourceNames { get; }
    public HashSet<string> GroupNames { get; }
    public uint? OverrideTtl { get; }
    public RewriteRule[] InlineRules { get; }
    public bool ResolutionFailed { get; }

    public bool MatchesGroups(HashSet<string> resolvedGroups)
    {
        if (GroupNames.Count == 0)
            return true;

        return GroupNames.Overlaps(resolvedGroups);
    }
}

internal sealed class SplitHorizonScope
{
    public string GroupName { get; init; }
    public bool? Enable { get; init; }
    public HashSet<string> SourceNames { get; init; }
    public HashSet<string> GroupNames { get; init; }
    public uint? OverrideTtl { get; init; }
    public bool OverrideTtlSpecified { get; init; }
    public RewriteRule[] InlineRules { get; init; }
}
