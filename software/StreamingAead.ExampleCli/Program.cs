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
