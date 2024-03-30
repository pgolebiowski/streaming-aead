using System.Diagnostics;

namespace StreamingAead.Tests.Interop.Utilities
{
    public static class TinkInterop
    {
        private static readonly string PythonCommand = "python3";
        private static readonly string ScriptPath = "../../../python/tink-cli.py";
        private static readonly string KeysetPath = "../../../python/keyset.txt";

        public static void Encrypt(string inputPath, string outputPath)
        {
            string arguments = BuildArguments("encrypt", inputPath, outputPath);
            ExecuteScript(PythonCommand, $"{ScriptPath} {arguments}");
        }

        public static void Decrypt(string inputPath, string outputPath)
        {
            string arguments = BuildArguments("decrypt", inputPath, outputPath);
            ExecuteScript(PythonCommand, $"{ScriptPath} {arguments}");
        }

        private static string BuildArguments(string mode, string inputPath, string outputPath)
        {
            return $"--mode={mode} --keyset_path={KeysetPath} --input_path={inputPath} --output_path={outputPath}";
        }

        private static void ExecuteScript(string command, string arguments)
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = command,
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };

            using var process = Process.Start(startInfo);
            if (process == null)
            {
                throw new InvalidOperationException("Failed to start Python process.");
            }

            process.WaitForExit();

            if (process.ExitCode != 0)
            {
                string error = process.StandardError.ReadToEnd();
                throw new InvalidOperationException($"Python script failed with exit code {process.ExitCode}: {error}");
            }
        }
    }
}
