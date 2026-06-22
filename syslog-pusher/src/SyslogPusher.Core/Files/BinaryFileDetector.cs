namespace SyslogPusher.Core.Files;

public static class BinaryFileDetector
{
    public static bool LooksBinary(ReadOnlySpan<byte> sample)
    {
        if (sample.IsEmpty)
            return false;

        if (sample.Length >= 2)
        {
            if (sample[0] == 0xFF && sample[1] == 0xFE)
                return false;
            if (sample[0] == 0xFE && sample[1] == 0xFF)
                return false;
        }

        if (sample.Length >= 3 && sample[0] == 0xEF && sample[1] == 0xBB && sample[2] == 0xBF)
            return false;

        var controlCount = 0;
        foreach (var b in sample)
        {
            if (b == 0)
                return true;

            if (b is 9 or 10 or 13)
                continue;

            if (b < 32 || b == 127)
                controlCount++;
        }

        return controlCount * 10 > sample.Length;
    }

    public static bool LooksBinary(string path, int sampleBytes)
    {
        try
        {
            using var stream = File.OpenRead(path);
            var buffer = new byte[Math.Min(sampleBytes, (int)Math.Max(0, stream.Length))];
            if (buffer.Length == 0)
                return false;

            var read = stream.Read(buffer, 0, buffer.Length);
            return LooksBinary(buffer.AsSpan(0, read));
        }
        catch
        {
            // Live logs can be briefly locked; do not permanently classify them as binary.
            return false;
        }
    }
}
