using System;

namespace RemoteRewrite;

internal static class AppLimits
{
    public const int MaxSourceBytes = 4 * 1024 * 1024;
    public const int MaxSources = 64;
    public const int MaxRules = 250_000;
    public const int MaxAppRecordCacheEntries = 1024;
    public const int MinimumRetrySeconds = 30;
    public const int MaximumRefreshSeconds = 7 * 24 * 60 * 60;
    public const uint MaximumTtl = 7 * 24 * 60 * 60;
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    public static readonly TimeSpan SourceTimeout = TimeSpan.FromSeconds(15);
}
