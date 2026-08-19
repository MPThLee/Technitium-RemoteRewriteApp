using System;
using System.Buffers;
using System.Collections.Generic;
using System.Linq;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal static class RuleMatcher
{
    public static RewriteMatch Match(
        IEnumerable<RewriteRule> primaryRules,
        IEnumerable<RewriteRule> secondaryRules,
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> requestedGroups,
        HashSet<string> resolvedGroups)
    {
        if ((requestedGroups.Count > 0) && !requestedGroups.Overlaps(resolvedGroups))
            return null;

        List<RewriteRule> primaryCandidates = new List<RewriteRule>();
        List<RewriteRule> exceptions = new List<RewriteRule>();
        int applicableRules = 0;

        // APP-record inline rules are the primary policy and have their own bounded parser.
        // sourceNames selects configured secondary sources only; it must not suppress inline rules.
        if (!Collect(primaryRules, qname, questionType, null, resolvedGroups, primaryCandidates, exceptions, ref applicableRules))
            return ResourceLimitExceeded();
        RemoveDisabled(primaryCandidates, exceptions);
        if (primaryCandidates.Count > 0)
            return BuildMatch(primaryCandidates);

        List<RewriteRule> secondaryCandidates = new List<RewriteRule>();
        if (!Collect(secondaryRules, qname, questionType, enabledSources, resolvedGroups, secondaryCandidates, exceptions, ref applicableRules))
            return ResourceLimitExceeded();
        RemoveDisabled(secondaryCandidates, exceptions);
        if (secondaryCandidates.Count == 0)
            return null;

        return BuildMatch(secondaryCandidates);
    }

    static void RemoveDisabled(List<RewriteRule> candidates, List<RewriteRule> exceptions)
    {
        if (exceptions.Count == 0)
            return;

        if (exceptions.Any(static exception => !exception.HasRewriteValue))
        {
            candidates.Clear();
            return;
        }

        HashSet<DnsResponseCode> emptyResponseCodes = new HashSet<DnsResponseCode>();
        HashSet<(DnsResponseCode ResponseCode, DnsResourceRecordType Type, string Value)> answerKeys = new();

        foreach (RewriteRule exception in exceptions)
        {
            if (exception.Answers.Length == 0)
            {
                emptyResponseCodes.Add(exception.ResponseCode);
                continue;
            }

            foreach (RewriteAnswer answer in exception.Answers)
                answerKeys.Add((exception.ResponseCode, answer.Type, answer.Value));
        }

        candidates.RemoveAll(candidate => candidate.Answers.Length == 0
            ? emptyResponseCodes.Contains(candidate.ResponseCode)
            : candidate.Answers.Any(answer => answerKeys.Contains((candidate.ResponseCode, answer.Type, answer.Value))));
    }

    static RewriteMatch BuildMatch(List<RewriteRule> candidates)
    {
        RewriteRule emptyResponse = candidates.FirstOrDefault(static rule => rule.Answers.Length == 0);
        if (emptyResponse is not null)
            return new RewriteMatch(emptyResponse.ResponseCode, new[] { emptyResponse });

        RewriteRule cname = candidates.FirstOrDefault(static rule => rule.Answers.Any(static answer => answer.Type == DnsResourceRecordType.CNAME));
        if (cname is not null)
            return new RewriteMatch(cname.ResponseCode, new[] { cname });

        DnsResponseCode responseCode = candidates[0].ResponseCode;
        return new RewriteMatch(responseCode, candidates.Where(rule => rule.ResponseCode == responseCode).ToArray());
    }

    public static RewriteRule Match(
        IEnumerable<RewriteRule> rules,
        string qname,
        HashSet<string> enabledSources,
        HashSet<string> requestedGroups,
        HashSet<string> resolvedGroups)
    {
        return Match(Array.Empty<RewriteRule>(), rules, qname, DnsResourceRecordType.ANY, enabledSources, requestedGroups, resolvedGroups)?.Rules.FirstOrDefault();
    }

    static bool Collect(
        IEnumerable<RewriteRule> rules,
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> resolvedGroups,
        List<RewriteRule> candidates,
        List<RewriteRule> exceptions,
        ref int applicableRules)
    {
        foreach (RewriteRule rule in rules)
        {
            if (enabledSources is not null && (enabledSources.Count > 0) && !enabledSources.Contains(rule.SourceName))
                continue;

            if (!rule.AppliesToGroups(resolvedGroups))
                continue;

            if (!rule.AppliesTo(questionType))
                continue;

            applicableRules++;
            if (applicableRules > AppLimits.MaxMatchingRulesPerRequest)
                return false;

            if (!rule.TryMatch(qname, out bool timedOut))
            {
                if (timedOut)
                    return false;
                continue;
            }

            if (rule.IsException)
                exceptions.Add(rule);
            else
                candidates.Add(rule);
        }

        return true;
    }

    static RewriteMatch ResourceLimitExceeded()
    {
        return new RewriteMatch(DnsResponseCode.ServerFailure, Array.Empty<RewriteRule>());
    }
}

internal sealed class RuleSet
{
    readonly Dictionary<string, Posting> _exact = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, Posting> _suffix = new(StringComparer.OrdinalIgnoreCase);
    readonly Dictionary<string, Posting> _bySource = new(StringComparer.OrdinalIgnoreCase);
    readonly Posting _anyQueryType = new Posting();
    readonly Dictionary<DnsResourceRecordType, Posting> _byQueryType = new();
    readonly Posting _anySourceGroup = new Posting();
    readonly Dictionary<string, Posting> _bySourceGroup = new(StringComparer.OrdinalIgnoreCase);
    readonly Posting _anyRuleGroup = new Posting();
    readonly Dictionary<string, Posting> _byRuleGroup = new(StringComparer.OrdinalIgnoreCase);
    readonly HashSet<string> _sourceNames = new(StringComparer.OrdinalIgnoreCase);
    readonly RewriteRule[] _indexed;
    readonly RewriteRule[] _dynamic;

    public RuleSet(IEnumerable<RewriteRule> rules)
    {
        List<RewriteRule> indexedRules = new List<RewriteRule>();
        List<RewriteRule> dynamicRules = new List<RewriteRule>();

        foreach (RewriteRule rule in rules.OrderBy(static rule => rule.Order))
        {
            if (rule.MatchType is MatchType.Glob or MatchType.Regex)
            {
                dynamicRules.Add(rule);
                continue;
            }

            int index = indexedRules.Count;
            indexedRules.Add(rule);

            switch (rule.MatchType)
            {
                case MatchType.Exact:
                    Add(_exact, rule.Pattern, index);
                    break;

                case MatchType.Suffix:
                    Add(_suffix, rule.Pattern, index);
                    break;
            }

            _sourceNames.Add(rule.SourceName);
            Add(_bySource, rule.SourceName, index);
            AddQueryTypes(rule, index);
            AddGroups(rule.SourceGroupNames, _anySourceGroup, _bySourceGroup, index);
            AddGroups(rule.RuleGroupNames, _anyRuleGroup, _byRuleGroup, index);
        }

        _indexed = indexedRules.ToArray();
        _dynamic = dynamicRules.ToArray();
        foreach (Posting posting in GetAllPostings())
            posting.Seal();
    }

    public IEnumerable<RewriteRule> GetCandidates(
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> resolvedGroups)
    {
        return MergeByOrder(new IEnumerable<RewriteRule>[]
        {
            GetIndexedCandidates(qname, questionType, enabledSources, resolvedGroups),
            _dynamic
        });
    }

    IEnumerable<RewriteRule> GetIndexedCandidates(
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> resolvedGroups)
    {
        if (_indexed.Length == 0)
            yield break;

        int wordCount = (_indexed.Length + 63) / 64;
        ulong[] candidates = ArrayPool<ulong>.Shared.Rent(wordCount);
        ulong[] filter = ArrayPool<ulong>.Shared.Rent(wordCount);
        Array.Clear(candidates, 0, wordCount);
        Array.Clear(filter, 0, wordCount);

        try
        {
            if (_exact.TryGetValue(qname, out Posting exact))
                exact.OrInto(candidates);

            string suffix = qname;
            while (!string.IsNullOrEmpty(suffix))
            {
                if (_suffix.TryGetValue(suffix, out Posting suffixRules))
                    suffixRules.OrInto(candidates);

                int dot = suffix.IndexOf('.');
                if (dot < 0)
                    break;
                suffix = suffix[(dot + 1)..];
            }

            if (IsEmpty(candidates, wordCount))
                yield break;

            if (enabledSources.Count > 0 && !enabledSources.IsSupersetOf(_sourceNames))
            {
                foreach (string sourceName in enabledSources)
                {
                    if (_bySource.TryGetValue(sourceName, out Posting sourceRules))
                        sourceRules.OrInto(filter);
                }
                IntersectWith(candidates, filter, wordCount);
                Array.Clear(filter, 0, wordCount);
            }

            if (questionType != DnsResourceRecordType.ANY)
            {
                _anyQueryType.OrInto(filter);
                if (_byQueryType.TryGetValue(questionType, out Posting queryTypeRules))
                    queryTypeRules.OrInto(filter);
                IntersectWith(candidates, filter, wordCount);
                Array.Clear(filter, 0, wordCount);
            }

            if (_anySourceGroup.Count != _indexed.Length)
            {
                _anySourceGroup.OrInto(filter);
                foreach (string groupName in resolvedGroups)
                {
                    if (_bySourceGroup.TryGetValue(groupName, out Posting groupRules))
                        groupRules.OrInto(filter);
                }
                IntersectWith(candidates, filter, wordCount);
                Array.Clear(filter, 0, wordCount);
            }

            if (_anyRuleGroup.Count != _indexed.Length)
            {
                _anyRuleGroup.OrInto(filter);
                foreach (string groupName in resolvedGroups)
                {
                    if (_byRuleGroup.TryGetValue(groupName, out Posting groupRules))
                        groupRules.OrInto(filter);
                }
                IntersectWith(candidates, filter, wordCount);
            }

            for (int wordIndex = 0; wordIndex < wordCount; wordIndex++)
            {
                ulong word = candidates[wordIndex];
                while (word != 0)
                {
                    int bit = System.Numerics.BitOperations.TrailingZeroCount(word);
                    int index = (wordIndex * 64) + bit;
                    if (index < _indexed.Length)
                        yield return _indexed[index];
                    word &= word - 1;
                }
            }
        }
        finally
        {
            ArrayPool<ulong>.Shared.Return(candidates);
            ArrayPool<ulong>.Shared.Return(filter);
        }
    }

    static bool IsEmpty(ulong[] words, int wordCount)
    {
        for (int index = 0; index < wordCount; index++)
        {
            if (words[index] != 0)
                return false;
        }
        return true;
    }

    static void IntersectWith(ulong[] candidates, ulong[] filter, int wordCount)
    {
        for (int index = 0; index < wordCount; index++)
            candidates[index] &= filter[index];
    }

    static IEnumerable<RewriteRule> MergeByOrder(IEnumerable<IEnumerable<RewriteRule>> sequences)
    {
        PriorityQueue<IEnumerator<RewriteRule>, int> queue = new PriorityQueue<IEnumerator<RewriteRule>, int>();
        foreach (IEnumerable<RewriteRule> sequence in sequences)
        {
            IEnumerator<RewriteRule> enumerator = sequence.GetEnumerator();
            if (enumerator.MoveNext())
                queue.Enqueue(enumerator, enumerator.Current.Order);
            else
                enumerator.Dispose();
        }

        try
        {
            while (queue.TryDequeue(out IEnumerator<RewriteRule> enumerator, out _))
            {
                RewriteRule rule = enumerator.Current;
                if (enumerator.MoveNext())
                    queue.Enqueue(enumerator, enumerator.Current.Order);
                else
                    enumerator.Dispose();
                yield return rule;
            }
        }
        finally
        {
            while (queue.TryDequeue(out IEnumerator<RewriteRule> enumerator, out _))
                enumerator.Dispose();
        }
    }

    void AddQueryTypes(RewriteRule rule, int index)
    {
        if (rule.QueryTypes.Count == 0)
        {
            _anyQueryType.Add(index);
            return;
        }

        foreach (DnsResourceRecordType queryType in rule.QueryTypes)
            Add(_byQueryType, queryType, index);
    }

    static void AddGroups(
        IReadOnlySet<string> groupNames,
        Posting unrestricted,
        Dictionary<string, Posting> index,
        int ruleIndex)
    {
        if (groupNames.Count == 0)
        {
            unrestricted.Add(ruleIndex);
            return;
        }

        foreach (string groupName in groupNames)
            Add(index, groupName, ruleIndex);
    }

    IEnumerable<Posting> GetAllPostings()
    {
        yield return _anyQueryType;
        yield return _anySourceGroup;
        yield return _anyRuleGroup;
        foreach (Posting posting in _exact.Values)
            yield return posting;
        foreach (Posting posting in _suffix.Values)
            yield return posting;
        foreach (Posting posting in _bySource.Values)
            yield return posting;
        foreach (Posting posting in _byQueryType.Values)
            yield return posting;
        foreach (Posting posting in _bySourceGroup.Values)
            yield return posting;
        foreach (Posting posting in _byRuleGroup.Values)
            yield return posting;
    }

    static void Add<TKey>(Dictionary<TKey, Posting> index, TKey key, int ruleIndex)
        where TKey : notnull
    {
        if (!index.TryGetValue(key, out Posting posting))
        {
            posting = new Posting();
            index.Add(key, posting);
        }
        posting.Add(ruleIndex);
    }

    sealed class Posting
    {
        readonly List<int> _indices = new List<int>();
        int[] _wordIndexes = Array.Empty<int>();
        ulong[] _words = Array.Empty<ulong>();
        int _count;

        public int Count => _count;

        public void Add(int index)
        {
            _indices.Add(index);
            _count++;
        }

        public void Seal()
        {
            if (_indices.Count == 0)
                return;

            List<int> wordIndexes = new List<int>();
            List<ulong> words = new List<ulong>();
            int currentWordIndex = -1;
            ulong currentWord = 0;

            foreach (int index in _indices)
            {
                int wordIndex = index / 64;
                if (wordIndex != currentWordIndex)
                {
                    if (currentWordIndex >= 0)
                    {
                        wordIndexes.Add(currentWordIndex);
                        words.Add(currentWord);
                    }
                    currentWordIndex = wordIndex;
                    currentWord = 0;
                }
                currentWord |= 1UL << (index % 64);
            }

            wordIndexes.Add(currentWordIndex);
            words.Add(currentWord);
            if (wordIndexes.Count * 3 >= _indices.Count)
                return;

            _wordIndexes = wordIndexes.ToArray();
            _words = words.ToArray();
            _indices.Clear();
            _indices.TrimExcess();
        }

        public void OrInto(ulong[] destination)
        {
            if (_wordIndexes.Length > 0)
            {
                for (int index = 0; index < _wordIndexes.Length; index++)
                    destination[_wordIndexes[index]] |= _words[index];
                return;
            }

            foreach (int index in _indices)
                destination[index / 64] |= 1UL << (index % 64);
        }
    }
}
