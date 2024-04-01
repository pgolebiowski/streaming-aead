[![][nuget-img]][nuget]

[nuget]:     https://www.nuget.org/packages/StreamingAead
[nuget-img]: https://badge.fury.io/nu/StreamingAead.svg

# Streaming AEAD for .NET

<img src="icon.jpg" width=30% height=30%>

This project offers a streaming encryption/decryption utility tailored for large datasets, conforming to [Google's Tink protocol](https://developers.google.com/tink/streaming-aead) for Streaming Authenticated Encryption with Associated Data (Streaming AEAD). Specifically, it offers a single static class `AES256_GCM_HKDF_1MB`, which can encrypt/decrypt a stream in 1 MB segments with AES-256 GCM and is interoperable with Tink for this particular configuration.

## Features ✨

This class hides the complexity of nonce and tag management, which is otherwise manual in `AesGcm`, allowing for a straightforward encryption experience, while offering properties:

- **Secrecy.** Nothing about the plaintext is disclosed, except for its length.
- **Authenticity.** Any alteration of the encrypted data is detectable, preventing unauthorized modifications.
- **Symmetry.** A single key is used for encryption and decryption.
- **Randomization.** Encryption is randomized so that identical plaintexts produce distinct ciphertexts.
- **Large volume.** The largest supported plaintext size is `2^32 * (2^20-16) ~= 2^51` bytes (about 2,000 TB).
- **Resource efficiency.** A fixed amount memory (~2 MB) is used during encryption and decryption.

Tested on datsets up to 5 TB that data encrypted with this library can be decrypted with Google's Tink and vice versa.

## Installation 📦

```
dotnet add package StreamingAead
```

## Show me the code 👩‍💻

```csharp
using System;
using System.Collections.Generic;
using System.Text;
using StreamingAead;

class Program
{
    static void Main(string[] unparsedArgs)
    {
        Arguments args = ParseArguments(unparsedArgs);

        if (string.IsNullOrEmpty(args.Mode) ||
            string.IsNullOrEmpty(args.KeyPath) ||
            string.IsNullOrEmpty(args.InputPath) ||
            string.IsNullOrEmpty(args.OutputPath))
        {
            Console.WriteLine("Missing required arguments.");
            return;
        }

        byte[] key = File.ReadAllBytes(args.KeyPath);
        byte[] associatedDataBytes = Encoding.UTF8.GetBytes(args.AssociatedData);

        using (var inputStream = File.OpenRead(args.InputPath))
        using (var outputStream = File.OpenWrite(args.OutputPath))
        {
            if (args.Mode == "encrypt")
            {
                AES256_GCM_HKDF_1MB.Encrypt(key, inputStream, outputStream, associatedDataBytes);
            }
            else if (args.Mode == "decrypt")
            {
                AES256_GCM_HKDF_1MB.Decrypt(key, inputStream, outputStream, associatedDataBytes);
            }
            else
            {
                Console.WriteLine($"Invalid mode: {args.Mode}");
                return;
            }
        }
    }

    record Arguments(string Mode, string KeyPath, string InputPath, string OutputPath, string AssociatedData);

    static Arguments ParseArguments(string[] args)
    {
        var argDictionary = new Dictionary<string, string>();
        for (int i = 0; i < args.Length; i += 2)
        {
            if (i + 1 < args.Length && args[i].StartsWith("--"))
            {
                string label = args[i].TrimStart('-');
                argDictionary[label] = args[i + 1];
            }
        }

        argDictionary.TryGetValue("mode", out var mode);
        argDictionary.TryGetValue("key-path", out var keyPath);
        argDictionary.TryGetValue("input-path", out var inputPath);
        argDictionary.TryGetValue("output-path", out var outputPath);
        argDictionary.TryGetValue("associated-data", out var associatedData);

        return new Arguments(
            Mode: mode ?? "",
            KeyPath: keyPath ?? "",
            InputPath: inputPath ?? "",
            OutputPath: outputPath ?? "",
            AssociatedData: associatedData ?? ""
        );
    }
}
```

## How it works under the hood 🔍

Please refer to [Tink's documentation](https://developers.google.com/tink/streaming-aead/aes_gcm_hkdf_streaming) for the details. For a security analysis of this algorithm, see [Security of Streaming Encryption in Google's Tink Library](https://eprint.iacr.org/2020/1019).

