using System;

namespace RemoteRewrite;

internal static class AppLimits
{
    public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
}
