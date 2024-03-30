using System.Buffers.Binary;
using System.Security.Cryptography;

namespace StreamingAead
{
    /// <summary>
    /// <para>Provides a streaming encryption/decryption service tailored for large datasets, conforming
    /// to <see href="https://developers.google.com/tink/streaming-aead">Google's Tink protocol</see>
    /// for Streaming Authenticated Encryption with Associated Data (Streaming AEAD).
    /// Specifically, it can encrypt/decrypt a stream in 1 MB segments with AES-256 GCM,
    /// and is interoperable with Tink for this particular configuration.</para>
    ///
    /// <para>This class hides the complexity of nonce and tag management, which is otherwise
    /// manual in <c>AesGcm</c>, allowing for a straightforward encryption experience,
    /// while offering properties:</para>
    ///
    /// <list type="bullet">
    ///   <item>
    ///     <term>Secrecy</term>
    ///     <description>Nothing about the plaintext is disclosed, except for its length.</description>
    ///   </item>
    ///   <item>
    ///     <term>Authenticity</term>
    ///     <description>Any alteration of the encrypted data is detectable, preventing unauthorized modifications.</description>
    ///   </item>
    ///   <item>
    ///     <term>Symmetry</term>
    ///     <description>A single key is used for encryption and decryption.</description>
    ///   </item>
    ///   <item>
    ///     <term>Randomization</term>
    ///     <description>Encryption is randomized so that identical plaintexts produce distinct ciphertexts.</description>
    ///   </item>
    ///   <item>
    ///     <term>Large volume</term>
    ///     <description>The largest supported plaintext size is <c>2^32 * (2^20-16) ~= 2^51</c> bytes (about 2,000 TB).</description>
    ///   </item>
    ///   <item>
    ///     <term>Resource efficiency</term>
    ///     <description>A fixed amount memory (~2 MB) is used during encryption and decryption.</description>
    ///   </item>
    /// </list>
    /// </summary>
    public static class AES256_GCM_HKDF_1MB
    {
        #region Constants

        /// <summary>
        /// The size of the derived key in bytes. Given the segment encryption algorithm
        /// is AES-256, this is chosen as 32 bytes (256 bits).
        /// </summary>
        private const int DerivedKeySize = 32;

        /// <summary>
        /// The nonce prefix length. This prefix is a part of the Initialization Vector (IV) construction
        /// for each encrypted segment. According to the Tink specification, this is fixed at 7 bytes.
        /// </summary>
        private const int NoncePrefixSize = 7;

        /// <summary>
        /// The size of the salt in bytes. According to the Tink specification, the salt is a uniform random sequence
        /// whose length matches the <see cref="DerivedKeySize"/>.
        /// </summary>
        private const int SaltSize = DerivedKeySize;

        /// <summary>
        /// The length of the header in bytes. According to the Tink specification, the header
        /// includes the salt, the nonce prefix, and a single byte to encode the header length itself.
        /// </summary>
        private const int HeaderSize = SaltSize + NoncePrefixSize + 1;

        /// <summary>
        /// The size of each encrypted segment, which consists of the ciphertext and the associated
        /// authentication tag. The size has been set to 1 MB, balancing performance and
        /// security for scenarios where large volumes of data are encrypted and integrity must be ensured.
        /// </summary>
        private const int AuthenticatedSegmentSize = 1 * 1024 * 1024;

        /// <summary>
        /// The segment number is 4 bytes long and uniquely identifies each segment in a sequence.
        /// It's encoded in the Initialization Vector (IV), ensuring every IV is unique.
        /// </summary>
        private const int SegmentNumberSize = 4;

        /// <summary>
        /// The size of the authentcation tag in bytes for each encrypted segment, as defined in the Tink specification.
        /// The tag is used for authentication and integrity verification of the ciphertext.
        /// </summary>
        private const int TagSize = 16;

        /// <summary>
        /// The size of the Initialization Vector (IV) in bytes, set to 12 to cover the nonce prefix,
        /// segment number, and a byte indicating if the segment is the last one. This configuration ensures
        /// a unique IV for each encryption operation in a given stream.
        /// </summary>
        private const int IvSize = NoncePrefixSize + SegmentNumberSize + 1;

        /// <summary>
        /// The byte value to be used in the Initialization Vector (IV) construction for all segments except the last.
        /// This value is appended to the IV to indicate that the segment is not the final one in the sequence.
        /// </summary>
        private const byte IvByteForIntermediateSegments = 0x00;

        /// <summary>
        /// The byte value to be appended to the Initialization Vector (IV) construction for the final segment.
        /// This value indicates the termination of the sequence of segments, protecting against truncation.
        /// </summary>
        private const byte IvByteForLastSegment = 0x01;

        /// <summary>
        /// According to the Tink specification, each segment should be encrypted with an empty
        /// associated data passed to AES-GCM. The user-facing associated data is used for key derivation instead.
        /// </summary>
        private static readonly byte[]? AssociatedDataForSegmentAuthentication = null;

        #endregion

        private readonly ref struct Header(ReadOnlySpan<byte> salt, ReadOnlySpan<byte> noncePrefix)
        {
            public ReadOnlySpan<byte> Salt { get; } = salt;
            public ReadOnlySpan<byte> NoncePrefix { get; } = noncePrefix;

            public static Header GenerateNew()
            {
                byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
                byte[] noncePrefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
                return new Header(salt: salt, noncePrefix: noncePrefix);
            }
        }

        private readonly ref struct Segment(ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag)
        {
            public ReadOnlySpan<byte> Ciphertext { get; } = ciphertext;
            public ReadOnlySpan<byte> Tag { get; } = tag;
        }

        #region Encryption

        /// <summary>
        /// Encrypts data from an input stream and writes the encrypted data to an output stream.
        /// This method divides the data into segments, encrypts each segment with AES-GCM using a derived key from HKDF,
        /// and writes the result sequentially to the output stream. Each segment includes an authentication tag
        /// for integrity verification. A header containing a salt and nonce prefix is generated
        /// and written to the start of the output stream.
        /// </summary>
        /// <param name="key">The secret key material for HKDF, used to derive the encryption key.</param>
        /// <param name="inputStream">The stream containing the plaintext data to be encrypted.</param>
        /// <param name="outputStream">The stream where the encrypted data will be written.</param>
        /// <param name="associatedData">The associated data to be authenticated but not encrypted.</param>
        public static void Encrypt(
            ReadOnlySpan<byte> key,
            Stream inputStream,
            Stream outputStream,
            ReadOnlySpan<byte> associatedData = default)
        {
            VerifyInputKeyMaterialSize(key.Length);

            Header header = Header.GenerateNew();
            WriteHeader(outputStream, header);

            ReadOnlySpan<byte> derivedKey = DeriveKey(key, header.Salt, associatedData);
            using var aesGcm = new AesGcm(key: derivedKey, tagSizeInBytes: TagSize);

            byte[] inputStreamBuffer = new byte[AuthenticatedSegmentSize];
            byte[] outputStreamBuffer = new byte[AuthenticatedSegmentSize];
            byte[] iv = new byte[IvSize];

            for (int segmentNumber = 0; ; segmentNumber++)
            {
                ReadOnlySpan<byte> plaintextChunk = ReadPlaintextChunk(
                    input: inputStream,
                    isFirstSegment: segmentNumber == 0,
                    buffer: inputStreamBuffer);

                bool isLastSegment = EndOfStreamReached(inputStream);

                ComputeIvForSegment(
                    noncePrefix: header.NoncePrefix,
                    segmentNumber,
                    isLastSegment,
                    iv: iv);

                Segment segment = EncryptSegment(
                    aesGcm: aesGcm,
                    iv: iv,
                    plaintext: plaintextChunk,
                    buffer: outputStreamBuffer);

                WriteSegment(outputStream, segment);

                if (isLastSegment)
                {
                    return;
                }
            }
        }

        private static void WriteHeader(Stream output, Header header)
        {
            output.WriteByte(HeaderSize);
            output.Write(header.Salt);
            output.Write(header.NoncePrefix);
        }

        private static void WriteSegment(Stream output, Segment segment)
        {
            output.Write(segment.Ciphertext);
            output.Write(segment.Tag);
        }

        /// <summary>
        /// Reads a chunk of plaintext data from the input stream for encryption. The size of the chunk is determined
        /// by the maximum segment size allowed, which accounts for the authentication tag and optionally the header
        /// if it's the first segment.
        /// </summary>
        private static ReadOnlySpan<byte> ReadPlaintextChunk(Stream input, bool isFirstSegment, Span<byte> buffer)
        {
            int maxConsumablePlaintextSize = AuthenticatedSegmentSize - TagSize - (isFirstSegment ? HeaderSize : 0);
            Span<byte> currentSegmentBuffer = buffer.Slice(0, maxConsumablePlaintextSize);

            int bytesRead = input.Read(currentSegmentBuffer);
            return currentSegmentBuffer.Slice(0, bytesRead);
        }

        private static Segment EncryptSegment(
            AesGcm aesGcm,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> plaintext,
            Span<byte> buffer)
        {
            Span<byte> ciphertext = buffer.Slice(0, plaintext.Length);
            Span<byte> tag = buffer.Slice(plaintext.Length, TagSize);

            aesGcm.Encrypt(
                nonce: iv,
                plaintext: plaintext,
                ciphertext: ciphertext,
                tag: tag,
                associatedData: AssociatedDataForSegmentAuthentication
            );

            return new Segment(
                ciphertext: ciphertext,
                tag: tag);
        }

        #endregion

        #region Decryption

        /// <summary>
        /// Decrypts data from an input stream and writes the decrypted data to an output stream.
        /// This method reads the encrypted data in segments, decrypts each segment with AES-GCM using a derived key from HKDF,
        /// and writes the decrypted plaintext sequentially to the output stream.
        /// </summary>
        /// <param name="key">The secret key material for HKDF, used to derive the decryption key.</param>
        /// <param name="inputStream">The stream containing the encrypted data to be decrypted.</param>
        /// <param name="outputStream">The stream where the decrypted plaintext will be written.</param>
        /// <param name="associatedData">The associated data that was authenticated but not encrypted.</param>
        public static void Decrypt(
            ReadOnlySpan<byte> key,
            Stream inputStream,
            Stream outputStream,
            ReadOnlySpan<byte> associatedData = default)
        {
            VerifyInputKeyMaterialSize(key.Length);

            Header header = ReadHeader(inputStream);
            ReadOnlySpan<byte> derivedKey = DeriveKey(key, header.Salt, associatedData);
            using var aesGcm = new AesGcm(key: derivedKey, tagSizeInBytes: TagSize);

            byte[] inputStreamBuffer = new byte[AuthenticatedSegmentSize];
            byte[] outputStreamBuffer = new byte[AuthenticatedSegmentSize];
            byte[] iv = new byte[IvSize];

            for (int segmentNumber = 0; ; segmentNumber++)
            {
                Segment segment = ReadSegment(
                    input: inputStream,
                    isFirstSegment: segmentNumber == 0,
                    buffer: inputStreamBuffer);

                bool isLastSegment = EndOfStreamReached(inputStream);

                ComputeIvForSegment(
                    noncePrefix: header.NoncePrefix,
                    segmentNumber,
                    isLastSegment,
                    iv: iv);

                ReadOnlySpan<byte> decryptedSegment = DecryptSegment(
                    aesGcm: aesGcm,
                    iv: iv,
                    segment: segment,
                    buffer: outputStreamBuffer);

                outputStream.Write(decryptedSegment);

                if (isLastSegment)
                {
                    return;
                }
            }
        }

        private static Header ReadHeader(Stream input)
        {
            int headerLength = input.ReadByte();
            if (headerLength == -1)
            {
                throw new EndOfStreamException("Stream is empty or error occurred reading header length.");
            }
            if (headerLength != HeaderSize)
            {
                throw new InvalidOperationException($"Invalid header length. Found {headerLength}, but expected {HeaderSize}.");
            }

            byte[] salt = new byte[SaltSize];
            byte[] noncePrefix = new byte[NoncePrefixSize];

            input.ReadExactly(salt);
            input.ReadExactly(noncePrefix);

            return new Header(
                salt: salt,
                noncePrefix: noncePrefix);
        }

        /// <summary>
        /// Reads an encrypted segment from the input stream, adjusting for header size if it's the first segment.
        /// According to the Tink specification, each segments has length that must be maximally chosen
        /// within the constraints.
        /// </summary>
        private static Segment ReadSegment(Stream input, bool isFirstSegment, Span<byte> buffer)
        {
            int maxPossibleSegmentSize = AuthenticatedSegmentSize - (isFirstSegment ? HeaderSize : 0);
            Span<byte> currentSegmentBuffer = buffer.Slice(0, maxPossibleSegmentSize);

            int actualSegmentSize = input.Read(currentSegmentBuffer);
            int ciphertextSize = actualSegmentSize - TagSize;

            ReadOnlySpan<byte> ciphertext = currentSegmentBuffer.Slice(0, ciphertextSize);
            ReadOnlySpan<byte> tag = currentSegmentBuffer.Slice(ciphertextSize, TagSize);

            return new Segment(
                ciphertext: ciphertext,
                tag: tag);
        }

        private static ReadOnlySpan<byte> DecryptSegment(
            AesGcm aesGcm,
            ReadOnlySpan<byte> iv,
            Segment segment,
            Span<byte> buffer)
        {
            Span<byte> decryptedData = buffer.Slice(0, segment.Ciphertext.Length);

            aesGcm.Decrypt(
                nonce: iv,
                ciphertext: segment.Ciphertext,
                tag: segment.Tag,
                plaintext: decryptedData,
                associatedData: AssociatedDataForSegmentAuthentication
            );

            return decryptedData;
        }

        #endregion

        private static void VerifyInputKeyMaterialSize(int size)
        {
            if (size < DerivedKeySize)
            {
                throw new ArgumentException($"The key material must be at least {DerivedKeySize} bytes long.");
            }
        }

        /// <summary>
        /// Derives a cryptographic key using the HKDF algorithm as specified by Tink.
        /// The length of the derived key matches <see cref="DerivedKeySize"/>,
        /// making it suitable for AES-256 encryption.
        /// </summary>
        private static ReadOnlySpan<byte> DeriveKey(
            ReadOnlySpan<byte> ikm,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> associatedData)
        {
            byte[] derivedKey = new byte[DerivedKeySize];

            HKDF.DeriveKey(
                hashAlgorithmName: HashAlgorithmName.SHA256,
                ikm: ikm,
                output: derivedKey,
                salt: salt,
                info: associatedData);

            return derivedKey;
        }

        private static void ComputeIvForSegment(
            ReadOnlySpan<byte> noncePrefix, int segmentNumber, bool isLastSegment, Span<byte> iv)
        {
            Span<byte> prefixSpan = iv.Slice(0, NoncePrefixSize);
            Span<byte> segmentNumberSpan = iv.Slice(NoncePrefixSize, SegmentNumberSize);
            Span<byte> isLastSegmentSpan = iv.Slice(IvSize - 1, 1);

            noncePrefix.CopyTo(prefixSpan);
            BinaryPrimitives.WriteInt32BigEndian(segmentNumberSpan, segmentNumber);
            isLastSegmentSpan[0] = isLastSegment ? IvByteForLastSegment : IvByteForIntermediateSegments;
        }

        private static bool EndOfStreamReached(Stream stream)
        {
            if (stream.CanSeek)
            {
                return stream.Position >= stream.Length;
            }

            throw new InvalidOperationException("The stream does not support seeking.");
        }
    }
}
