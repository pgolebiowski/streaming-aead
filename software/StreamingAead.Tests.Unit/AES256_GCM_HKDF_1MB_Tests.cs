using Xunit;
using Shouldly;
using System.Security.Cryptography;

namespace StreamingAead.Tests.Unit;

public class AES256_GCM_HKDF_1MB_Tests
{
    /// <summary>
    /// Iterates through various data sizes to ensure that encryption and decryption
    /// correctly handle various input sizes, especially across segment boundaries.
    /// </summary>
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(10)]
    [InlineData(512)]
    [InlineData(1024 * 4)] // 4 KB
    [InlineData(1024 * 1024 - 40 - 16)] // Maximum data that fits in one segment
    [InlineData(1024 * 1024 - 40 - 16 + 1)] // Data that spans two segments
    [InlineData(1024 * 1024 * 5)] // 5 MB
    [InlineData(1024 * 1024 * 100)] // 100 MB
    public void RoundTripEncryptDecrypt_SmallHandPicked(int dataSize)
    {
        this.RoundTripEncryptDecrypt(dataSize);
    }

    /// <summary>
    /// Iterates through data sizes from 0 bytes to 10 MB in 1-byte increments.
    /// This test is designed to be executed on demand due to its significant resource usage.
    /// </summary>
    [Fact]
    [Trait(Traits.Category, Traits.HeavyCompute)]
    public void RoundTripEncryptDecrypt_0MB_10MB()
    {
        const int endSize = 10 * 1024 * 1024; // 10 MB
        IEnumerable<int> dataSizes = Enumerable.Range(0, endSize + 1);

        int processedCount = 0;

        Parallel.ForEach(
            source: dataSizes,
            parallelOptions: new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            },
            dataSize =>
            {
                RoundTripEncryptDecrypt(dataSize);

                int currentCount = Interlocked.Increment(ref processedCount);

                // Report progress every 0.01%
                if (currentCount % (endSize / 10_000) == 0)
                {
                    Console.WriteLine($"Progress: {currentCount / (double)endSize:P2}");
                }
            }
        );
    }

    private void RoundTripEncryptDecrypt(int dataSize)
    {
        // given
        byte[] key = GenerateRandomData(32);
        byte[] originalData = GenerateRandomData(dataSize);
        byte[] associatedData = GenerateRandomData(16);

        // when
        (byte[] decryptedData, long encryptedDataSize)
            = PerformRoundTripEncryptionAndDecryption(key, originalData, associatedData);

        // then
        originalData.SequenceEqual(decryptedData).ShouldBeTrue();
        encryptedDataSize.ShouldBe(ComputeExpectedEncryptedDataSize(dataSize));
    }

    /// <summary>
    /// Verifies the encryption and decryption process for extremely large data sizes.
    /// </summary>
    [Theory]
    [Trait(Traits.Category, Traits.LargeStorage)]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(5)]
    [InlineData(25)]
    [InlineData(100)]
    [InlineData(250)]
    [InlineData(500)]
    [InlineData(1024)] // 1 TB
    [InlineData(1024 * 5)] // 5 TB
    public void RoundTripEncryptDecrypt_LargeHandPicked(long dataSizeInGB)
    {
        // given
        byte[] key = GenerateRandomData(200);
        byte[] associatedData = GenerateRandomData(1024 * 1024);

        long encryptedDataSize;
        long dataSize = dataSizeInGB * 1024 * 1024 * 1024;

        using TestEnvironment env = TestEnvironment.Initialize(dataSize);
        Console.WriteLine($"Original file ({dataSizeInGB} GB): {env.OriginalFilePath}");

        // when
        using (var originalFileStream = new FileStream(env.OriginalFilePath, FileMode.Open, FileAccess.Read))
        using (var encryptedFileStream = new FileStream(env.EncryptedFilePath, FileMode.Create, FileAccess.Write))
        {
            AES256_GCM_HKDF_1MB.Encrypt(key, originalFileStream, encryptedFileStream, associatedData);
            Console.WriteLine($"Encrypted file ({dataSizeInGB} GB): {env.EncryptedFilePath}");

            encryptedDataSize = encryptedFileStream.Length;
        }

        using (var encryptedFileStream = new FileStream(env.EncryptedFilePath, FileMode.Open, FileAccess.Read))
        using (var decryptedFileStream = new FileStream(env.DecryptedFilePath, FileMode.Create, FileAccess.Write))
        {
            AES256_GCM_HKDF_1MB.Decrypt(key, encryptedFileStream, decryptedFileStream, associatedData);
            Console.WriteLine($"Decrypted file ({dataSizeInGB} GB): {env.DecryptedFilePath}");
        }

        // then
        encryptedDataSize.ShouldBe(ComputeExpectedEncryptedDataSize(dataSize));
        env.CheckIfOriginalAndDecryptedFilesAreEqual().ShouldBeTrue();
    }

    /// <summary>
    /// Verifies that any form of tampering with the encrypted data
    /// is reliably detected during the decryption.
    /// </summary>
    [Theory]
    [InlineData(15)] // Header salt
    [InlineData(35)] // Header nonce prefix
    [InlineData(1000)] // Segment ciphertext
    [InlineData(1045)] // Segment authentication tag
    [InlineData(1055)] // Last byte
    public void Decrypt_WhenDataIsTampered_ThrowsAuthenticationTagMismatchException(int byteToAlter)
    {
        // given
        byte[] key = GenerateRandomData(32);
        byte[] originalData = GenerateRandomData(1000);

        byte[] encryptedData = PerformEncryption(key, originalData);
        encryptedData.Length.ShouldBe(40 + 16 + 1000); // Header plus one segment

        Action action = () => PerformDecryption(key, encryptedData);

        // when & then
        action.ShouldNotThrow();
        encryptedData[byteToAlter] ^= 0xFF; // Flip the byte
        action.ShouldThrow<AuthenticationTagMismatchException>();
    }

    /// <summary>
    /// Ensures that changing the associated data between encryption and decryption
    /// fails the decryption process, adhering to the AEAD property of authenticity.
    /// </summary>
    [Fact]
    public void Decrypt_WhenAssociatedDataIsTampered_ThrowsAuthenticationTagMismatchException()
    {
        // given
        byte[] key = GenerateRandomData(32);
        byte[] originalData = GenerateRandomData(1000);
        byte[] associatedData = GenerateRandomData(16);

        byte[] encryptedData = PerformEncryption(key, originalData, associatedData);
        Action action = () => PerformDecryption(key, encryptedData, associatedData);

        // when & then
        action.ShouldNotThrow();
        associatedData[0] ^= 0xFF; // Alter the first byte
        action.ShouldThrow<AuthenticationTagMismatchException>();
    }

    [Theory]
    [InlineData(500)] // entire 3rd segment
    [InlineData(250)]
    [InlineData(1)]
    [InlineData(501)] // entire 3rd segment and 1 byte off the 2nd segment
    [InlineData(1024 * 1024 + 500)] // entire 3rd and 2nd segments
    public void Decrypt_WhenSegmentsAreTruncated_ThrowsAuthenticationTagMismatchException(int bytesToTruncate)
    {
        // given
        byte[] key = GenerateRandomData(32);

        int[] segmentDataSizes =
        [
            1024 * 1024 - 40 - 16,
            1024 * 1024 - 16,
            500 - 16
        ];

        byte[] originalData = GenerateRandomData(segmentDataSizes.Sum());
        byte[] encryptedData = PerformEncryption(key, originalData);
        encryptedData.Length.ShouldBe(segmentDataSizes.Sum() + 40 + 3 * 16);

        // when
        byte[] truncatedEncryptedData = encryptedData
            .AsSpan(0, encryptedData.Length - bytesToTruncate)
            .ToArray();

        // then
        Action action1 = () => PerformDecryption(key, encryptedData);
        Action action2 = () => PerformDecryption(key, truncatedEncryptedData);
        action1.ShouldNotThrow();
        action2.ShouldThrow<AuthenticationTagMismatchException>();
    }

    /// <summary>
    /// Confirms that encrypting the same plaintext multiple times with the same key
    /// results in different ciphertexts, verifying the implementation's use of
    /// nonce for encryption randomization.
    /// </summary>
    [Fact]
    public void RandomizationVerification_ShouldProduceDifferentCiphertexts()
    {
        // given
        byte[] key = GenerateRandomData(32);
        byte[] originalData = GenerateRandomData(1000);
        byte[] associatedData = GenerateRandomData(16);

        // when
        byte[] encryptedData1 = PerformEncryption(key, originalData, associatedData);
        byte[] encryptedData2 = PerformEncryption(key, originalData, associatedData);

        // then
        encryptedData1.SequenceEqual(encryptedData2).ShouldBeFalse();
    }

    [Theory]
    [InlineData(0, true)]
    [InlineData(1, true)]
    [InlineData(31, true)]
    [InlineData(32, false)]
    [InlineData(50, false)]
    [InlineData(100, false)]
    public void Encrypt_WhenKeyMaterialIsInvalid_ShouldThrowArgumentException(int inputKeyMaterialSize, bool shouldThrow)
    {
        // given
        byte[] key = GenerateRandomData(inputKeyMaterialSize);
        byte[] originalData = GenerateRandomData(1000);
        byte[] associatedData = GenerateRandomData(16);
        using var inputStream = new MemoryStream(originalData);
        using var outputStream = new MemoryStream();

        // when
        Action encryptAction = () => AES256_GCM_HKDF_1MB.Encrypt(key, inputStream, outputStream, associatedData);

        // then
        if (shouldThrow)
        {
            encryptAction.ShouldThrow<ArgumentException>("The key material must be at least 32 bytes long.");
        }
        else
        {
            encryptAction.ShouldNotThrow();
        }
    }

    private static byte[] GenerateRandomData(int size)
    {
        byte[] data = new byte[size];
        RandomNumberGenerator.Fill(data);
        return data;
    }

    private static (byte[] DecryptedData, long EncryptedDataSize) PerformRoundTripEncryptionAndDecryption(
        ReadOnlySpan<byte> key,
        byte[] originalData,
        ReadOnlySpan<byte> associatedData = default)
    {
        byte[] encryptedData = PerformEncryption(key, originalData, associatedData);
        byte[] decryptedData = PerformDecryption(key, encryptedData, associatedData);

        return (decryptedData, encryptedData.Length);
    }

    private static byte[] PerformEncryption(
        ReadOnlySpan<byte> key,
        byte[] originalData,
        ReadOnlySpan<byte> associatedData = default)
    {
        using var originalDataStream = new MemoryStream(originalData);
        using var encryptedDataStream = new MemoryStream();

        AES256_GCM_HKDF_1MB.Encrypt(key, originalDataStream, encryptedDataStream, associatedData);

        return encryptedDataStream.ToArray();
    }

    private static byte[] PerformDecryption(
        ReadOnlySpan<byte> key,
        byte[] encryptedData,
        ReadOnlySpan<byte> associatedData = default)
    {
        using var encryptedDataStream = new MemoryStream(encryptedData);
        using var decryptedDataStream = new MemoryStream();

        AES256_GCM_HKDF_1MB.Decrypt(key, encryptedDataStream, decryptedDataStream, associatedData);

        return decryptedDataStream.ToArray();
    }

    private static long ComputeExpectedEncryptedDataSize(long originalDataSize)
    {
        // Each segment except the first one can contain up to 1024 * 1024 - 16 bytes of data.
        // The first segment's capacity is reduced by an additional 40 bytes due to the header.
        // For simplification, we'll include this header size in our initial data size calculation
        // and then distribute the total data across the necessary number of segments.
        const int segmentCapacity = 1024 * 1024 - 16;
        long originalDataWithHeaderSize = originalDataSize + 40;

        long result = 0;

        long numberOfSegments = (long)Math.Ceiling((decimal)originalDataWithHeaderSize / segmentCapacity);
        if (numberOfSegments > 1)
        {
            // count full segments except the last one
            result += (numberOfSegments - 1) * 1024 * 1024;
        }

        long dataLeftSize = originalDataWithHeaderSize - ((numberOfSegments - 1) * segmentCapacity);
        long lastSegmentSize = dataLeftSize + 16;
        result += lastSegmentSize;

        return result;
    }
}
