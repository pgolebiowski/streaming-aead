using StreamingAead.Tests.Interop.Utilities;
using Xunit;
using Shouldly;

namespace StreamingAead.Tests.Interop
{
    public class AES256_GCM_HKDF_1MB_Tests
    {
        public static IEnumerable<object[]> DataSizes =>
        [
            [1],
            [2],
            [512],
            [1024 * 1024 - 40 - 16], // The maximum number of bytes that can fit in one segment
            [1024 * 1024 - 40 - 16 + 1], // This size will result in the creation of two segments
            [1024 * 1024 * 4],
            [1024 * 1024 * 100],
            [1024L * 1024 * 1024 * 3]
        ];

        [Theory]
        [MemberData(nameof(DataSizes))]
        public void EncryptWithLibraryThenDecryptWithTink_Small(long dataSize)
        {
            EncryptWithLibraryThenDecryptWithTink(dataSize);
        }

        [Theory]
        [MemberData(nameof(DataSizes))]
        public void EncryptWithTinkThenDecryptWithLibrary_Small(long dataSize)
        {
            EncryptWithTinkThenDecryptWithLibrary(dataSize);
        }

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
        public void BidirectionalInteropTest_Large(long dataSizeInGB)
        {
            Console.WriteLine($"Data size: {dataSizeInGB}");
            long dataSize = dataSizeInGB * 1024 * 1024 * 1024;

            EncryptWithLibraryThenDecryptWithTink(dataSize);
            EncryptWithTinkThenDecryptWithLibrary(dataSize);
        }

        private static void EncryptWithLibraryThenDecryptWithTink(long dataSize)
        {
            using TestEnvironment env = TestEnvironment.Initialize(dataSize);

            DotnetLibrary.Encrypt(env.OriginalFilePath, env.EncryptedFilePath);
            TinkInterop.Decrypt(env.EncryptedFilePath, env.DecryptedFilePath);

            env.CheckIfOriginalAndDecryptedFilesAreEqual().ShouldBeTrue();
        }

        private static void EncryptWithTinkThenDecryptWithLibrary(long dataSize)
        {
            using TestEnvironment env = TestEnvironment.Initialize(dataSize);

            TinkInterop.Encrypt(env.OriginalFilePath, env.EncryptedFilePath);
            DotnetLibrary.Decrypt(env.EncryptedFilePath, env.DecryptedFilePath);

            env.CheckIfOriginalAndDecryptedFilesAreEqual().ShouldBeTrue();
        }
    }
}
