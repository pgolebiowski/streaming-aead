namespace StreamingAead.Tests;

public static class StreamComparer
{
    public static bool AreEqual(Stream stream1, Stream stream2)
    {
        const int bufferSize = 1024 * 1024;
        byte[] buffer1 = new byte[bufferSize];
        byte[] buffer2 = new byte[bufferSize];

        if (stream1.Length != stream2.Length)
        {
            // Different lengths mean the streams are not equal
            return false;
        }

        stream1.Seek(0, SeekOrigin.Begin);
        stream2.Seek(0, SeekOrigin.Begin);

        int bytesRead1, bytesRead2;
        do
        {
            bytesRead1 = stream1.Read(buffer1, 0, bufferSize);
            bytesRead2 = stream2.Read(buffer2, 0, bufferSize);

            if (bytesRead1 != bytesRead2)
            {
                throw new Exception(
                    "The number of bytes read from the streams is different, even though that are of equal lengths.");
            }

            ReadOnlySpan<byte> span1 = buffer1.AsSpan(0, bytesRead1);
            ReadOnlySpan<byte> span2 = buffer2.AsSpan(0, bytesRead2);

            if (!span1.SequenceEqual(span2))
            {
                // Found a difference in the streams' data
                return false;
            }
        } while (bytesRead1 > 0 && bytesRead2 > 0);

        // The streams are equal
        return true;
    }
}
