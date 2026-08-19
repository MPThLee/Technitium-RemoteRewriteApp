using System;
using System.Collections.Generic;
using System.Text.Json;

namespace RemoteRewrite;

internal static class JsonObjectValidation
{
    public static void RequireUniqueProperties(JsonElement value, string context)
    {
        if (value.ValueKind != JsonValueKind.Object)
            throw new FormatException($"{context} must be a JSON object.");

        HashSet<string> properties = new HashSet<string>(StringComparer.Ordinal);
        foreach (JsonProperty property in value.EnumerateObject())
        {
            if (!properties.Add(property.Name))
                throw new FormatException($"{context} contains duplicate property '{property.Name}'.");
        }
    }
}
