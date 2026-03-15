using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;

namespace RemoteRewrite;

internal sealed class AppRecordOptions
{
    static readonly AppRecordOptions Empty = new AppRecordOptions
    {
        Enable = true,
        SourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        GroupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
        OverrideTtl = null,
        InlineRules = Array.Empty<RewriteRule>(),
        SplitHorizonScopes = Array.Empty<SplitHorizonScope>()
    };
    static readonly ConcurrentDictionary<string, AppRecordOptions> _cache = new ConcurrentDictionary<string, AppRecordOptions>(StringComparer.Ordinal);

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

        return _cache.GetOrAdd(appRecordData, static data => ParseCore(data));
    }

    public AppRecordEffectiveOptions Resolve(HashSet<string> resolvedGroups)
    {
        foreach (SplitHorizonScope scope in SplitHorizonScopes)
        {
            if (resolvedGroups.Contains(scope.GroupName))
            {
                return new AppRecordEffectiveOptions(
                    scope.Enable,
                    scope.SourceNames.Count > 0 ? scope.SourceNames : SourceNames,
                    scope.GroupNames.Count > 0 ? scope.GroupNames : GroupNames,
                    scope.OverrideTtl ?? OverrideTtl,
                    scope.InlineRules.Length > 0 ? scope.InlineRules : InlineRules
                );
            }
        }

        return new AppRecordEffectiveOptions(Enable, SourceNames, GroupNames, OverrideTtl, InlineRules);
    }

    public bool MatchesGroups(HashSet<string> resolvedGroups)
    {
        return Resolve(resolvedGroups).MatchesGroups(resolvedGroups);
    }

    static AppRecordOptions ParseCore(string appRecordData)
    {
        using JsonDocument document = JsonDocument.Parse(appRecordData);
        JsonElement root = document.RootElement;
        int inlineOrder = 0;

        return new AppRecordOptions
        {
            Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            SourceNames = root.TryGetProperty("sourceNames", out JsonElement sourceNames)
                ? ParseStringArray(sourceNames)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            GroupNames = root.TryGetProperty("groupNames", out JsonElement groupNames)
                ? ParseStringArray(groupNames)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            OverrideTtl = root.TryGetProperty("overrideTtl", out JsonElement ttl) && (ttl.ValueKind == JsonValueKind.Number)
                ? ttl.GetUInt32()
                : null,
            InlineRules = ParseInlineRules(root, "inlineSources", "__apprecord_inline", ref inlineOrder),
            SplitHorizonScopes = ParseSplitHorizonMap(root, ref inlineOrder)
        };
    }

    static RewriteRule[] ParseInlineRules(JsonElement item, string propertyName, string sourcePrefix, ref int order)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement inlineSources) || (inlineSources.ValueKind != JsonValueKind.Array))
            return Array.Empty<RewriteRule>();

        List<RewriteRule> rules = new List<RewriteRule>();
        int index = 0;

        foreach (JsonElement inlineSource in inlineSources.EnumerateArray())
        {
            SourceConfig source = SourceConfig.Parse(inlineSource, $"{sourcePrefix}_{index++}");
            if (!source.Enable || string.IsNullOrWhiteSpace(source.Text))
                continue;

            switch (source.Format)
            {
                case SourceFormat.AdGuardFilter:
                    rules.AddRange(RuleParser.ParseAdGuardFilterSource(source, source.Text, ref order));
                    break;

                case SourceFormat.RewriteRulesJson:
                    rules.AddRange(RuleParser.ParseRewriteRulesJsonSource(source, source.Text, ref order));
                    break;
            }
        }

        return rules.ToArray();
    }

    static SplitHorizonScope[] ParseSplitHorizonMap(JsonElement root, ref int order)
    {
        if (!root.TryGetProperty("splitHorizonMap", out JsonElement splitHorizonMap) || (splitHorizonMap.ValueKind != JsonValueKind.Object))
            return Array.Empty<SplitHorizonScope>();

        List<SplitHorizonScope> scopes = new List<SplitHorizonScope>();

        foreach (JsonProperty property in splitHorizonMap.EnumerateObject())
        {
            if (property.Value.ValueKind != JsonValueKind.Object)
                continue;

            JsonElement value = property.Value;
            scopes.Add(new SplitHorizonScope
            {
                GroupName = property.Name.Trim().ToLowerInvariant(),
                Enable = value.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                SourceNames = value.TryGetProperty("sourceNames", out JsonElement sourceNames)
                    ? ParseStringArray(sourceNames)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                GroupNames = value.TryGetProperty("groupNames", out JsonElement groupNames)
                    ? ParseStringArray(groupNames)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                OverrideTtl = value.TryGetProperty("overrideTtl", out JsonElement overrideTtl) && (overrideTtl.ValueKind == JsonValueKind.Number)
                    ? overrideTtl.GetUInt32()
                    : null,
                InlineRules = ParseInlineRules(value, "inlineSources", $"__split_{property.Name}", ref order)
            });
        }

        return scopes.ToArray();
    }

    static HashSet<string> ParseStringArray(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Array)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        return new HashSet<string>(
            value.EnumerateArray()
                .Where(static entry => entry.ValueKind == JsonValueKind.String)
                .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
            StringComparer.OrdinalIgnoreCase
        );
    }
}

internal sealed class AppRecordEffectiveOptions
{
    public AppRecordEffectiveOptions(bool enable, HashSet<string> sourceNames, HashSet<string> groupNames, uint? overrideTtl, RewriteRule[] inlineRules)
    {
        Enable = enable;
        SourceNames = sourceNames;
        GroupNames = groupNames;
        OverrideTtl = overrideTtl;
        InlineRules = inlineRules;
    }

    public bool Enable { get; }
    public HashSet<string> SourceNames { get; }
    public HashSet<string> GroupNames { get; }
    public uint? OverrideTtl { get; }
    public RewriteRule[] InlineRules { get; }

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
    public bool Enable { get; init; }
    public HashSet<string> SourceNames { get; init; }
    public HashSet<string> GroupNames { get; init; }
    public uint? OverrideTtl { get; init; }
    public RewriteRule[] InlineRules { get; init; }
}
