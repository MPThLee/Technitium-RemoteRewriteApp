using System;

namespace RemoteRewrite;

internal static class AppLimits
{
    public const int MaxSourceBytes = 4 * 1024 * 1024;
    public const int MaxConfigBytes = 8 * 1024 * 1024;
    public const int MaxAppRecordBytes = 256 * 1024;
    public const int MaxSources = 64;
    public const int MaxRules = 250_000;
    public const int MaxAppRecordRules = 2048;
    public const int MaxRegexRules = 1024;
    public const int MaxAppRecordRegexRules = 128;
    public const int MaxPatternLength = 1024;
    public const int MaxAnswersPerRule = 64;
    public const int MaxAnswerMemberships = 500_000;
    public const int MaxGroupIndexMemberships = 500_000;
    public const int MaxQueryTypeMemberships = 500_000;
    public const int MaxAppRecordAnswerMemberships = 4096;
    public const int MaxAppRecordGroupIndexMemberships = 4096;
    public const int MaxAppRecordQueryTypeMemberships = 4096;
    public const int MaxAnswersPerResponse = 64;
    public const int MaxMatchingRulesPerRequest = 4096;
    public const int MaxSplitHorizonScopes = 64;
    public const int MaxSplitHorizonMapEntries = 64;
    public const int MaxGroupNameLength = 128;
    public const int MaxDomainNameLength = 253;
    public const int MaxAppRecordCacheEntries = 64;
    public const int MinimumRetrySeconds = 30;
    public const int MaximumRefreshSeconds = 7 * 24 * 60 * 60;
    public const uint MaximumTtl = 7 * 24 * 60 * 60;
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    public static readonly TimeSpan SourceTimeout = TimeSpan.FromSeconds(15);
}
