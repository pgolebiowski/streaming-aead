using System.Security.Cryptography;

namespace StreamingAead.Tests;

public class TestEnvironment : IDisposable
{
    private readonly TestFilePaths files;
    private bool disposed = false;

    private record TestFilePaths(string OriginalFilePath, string EncryptedFilePath, string DecryptedFilePath);

    private TestEnvironment(TestFilePaths files)
    {
        this.files = files;
    }

    public string OriginalFilePath => this.files.OriginalFilePath;
    public string EncryptedFilePath => this.files.EncryptedFilePath;
    public string DecryptedFilePath => this.files.DecryptedFilePath;

    public static TestEnvironment Initialize(long originalFileSizeInBytes)
    {
        string originalFilePath = Path.GetTempFileName();
        string encryptedFilePath = Path.GetTempFileName();
        string decryptedFilePath = Path.GetTempFileName();

        using (var fileStream = new FileStream(originalFilePath, FileMode.Create, FileAccess.Write))
        {
            FillStreamWithRandomData(fileStream, originalFileSizeInBytes);
        }

        var paths = new TestFilePaths(originalFilePath, encryptedFilePath, decryptedFilePath);
        return new TestEnvironment(paths);
    }

    public bool CheckIfOriginalAndDecryptedFilesAreEqual()
    {
        using (var originalFileStream = new FileStream(this.OriginalFilePath, FileMode.Open))
        using (var decryptedFileStream = new FileStream(this.DecryptedFilePath, FileMode.Open))
        {
            return StreamComparer.AreEqual(originalFileStream, decryptedFileStream);
        }
    }

    public void Dispose()
    {
        if (!this.disposed)
        {
            File.Delete(this.OriginalFilePath);
            File.Delete(this.EncryptedFilePath);
            File.Delete(this.DecryptedFilePath);

            this.disposed = true;
        }
    }

    private static void FillStreamWithRandomData(Stream stream, long dataSize)
    {
        const int patternSize = 1024 * 1024 * 20; // 20 MB
        byte[] pattern = new byte[patternSize];

        using (var random = RandomNumberGenerator.Create())
        {
            random.GetBytes(pattern);
        }

        long writtenBytes = 0;
        while (writtenBytes < dataSize)
        {
            long remainingBytes = dataSize - writtenBytes;
            int bytesToWrite = remainingBytes > patternSize ? patternSize : (int)remainingBytes;
            stream.Write(pattern, 0, bytesToWrite);
            writtenBytes += bytesToWrite;
        }
    }
}
