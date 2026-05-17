namespace SyslogPusher.Core.Files;

public static class FilePatternMatcher
{
    public static bool MatchesAny(string fileName, IEnumerable<string> patterns)
    {
        foreach (var pattern in patterns)
        {
            if (string.IsNullOrWhiteSpace(pattern))
                continue;

            if (Matches(fileName, pattern.Trim()))
                return true;
        }

        return false;
    }

    private static bool Matches(string fileName, string pattern)
    {
        if (pattern == "*")
            return true;

        if (!pattern.Contains('*', StringComparison.Ordinal))
            return string.Equals(fileName, pattern, StringComparison.OrdinalIgnoreCase);

        return SimpleWildcardMatch(fileName, pattern);
    }

    private static bool SimpleWildcardMatch(string input, string pattern)
    {
        var inputIndex = 0;
        var patternIndex = 0;
        var starIndex = -1;
        var matchIndex = 0;

        while (inputIndex < input.Length)
        {
            if (patternIndex < pattern.Length &&
                (pattern[patternIndex] == input[inputIndex] ||
                 char.ToUpperInvariant(pattern[patternIndex]) == char.ToUpperInvariant(input[inputIndex])))
            {
                inputIndex++;
                patternIndex++;
                continue;
            }

            if (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            {
                starIndex = patternIndex;
                matchIndex = inputIndex;
                patternIndex++;
                continue;
            }

            if (starIndex != -1)
            {
                patternIndex = starIndex + 1;
                matchIndex++;
                inputIndex = matchIndex;
                continue;
            }

            return false;
        }

        while (patternIndex < pattern.Length && pattern[patternIndex] == '*')
            patternIndex++;

        return patternIndex == pattern.Length;
    }
}
