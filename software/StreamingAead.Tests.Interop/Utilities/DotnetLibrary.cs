namespace StreamingAead.Tests.Interop.Utilities
{
    public static class DotnetLibrary
    {
        public static void Encrypt(string inputPath, string outputPath)
        {
            ProcessFile(inputPath, outputPath, modeIsEncrypt: true);
        }

        public static void Decrypt(string inputPath, string outputPath)
        {
            ProcessFile(inputPath, outputPath, modeIsEncrypt: false);
        }

        private static void ProcessFile(string inputPath, string outputPath, bool modeIsEncrypt)
        {
            byte[] key = GetHardcodedKey();
            byte[] aad = new byte[0];

            using FileStream inputFileStream = new(inputPath, FileMode.Open, FileAccess.Read);
            using FileStream outputFileStream = new(outputPath, FileMode.Create, FileAccess.Write);

            if (modeIsEncrypt)
            {
                AES256_GCM_HKDF_1MB.Encrypt(key, inputFileStream, outputFileStream, aad);
            }
            else
            {
                AES256_GCM_HKDF_1MB.Decrypt(key, inputFileStream, outputFileStream, aad);
            }
        }

        private static byte[] GetHardcodedKey()
        {
            string base64Key = "eBi3/vnCbYIIDku0hPD+vCYVUAef5/05wOOsks5db4s=";
            return Convert.FromBase64String(base64Key);
        }
    }
}
