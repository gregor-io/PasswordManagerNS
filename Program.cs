using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace PasswordManagerNS
{
    class Program
    {
        public static void Main()
        {
            // get password from user
            Console.WriteLine("Please enter your password:");
            var password = Console.ReadLine();

            var key = GenerateRandomKey();
            var iv = GenerateRandomIv();

            var encrypted = EncryptPassword(password, key, iv);
            var encryptedHex = BitConverter.ToString(encrypted).Replace("-", "");
            Console.WriteLine(encryptedHex);
            Console.WriteLine(DecryptPassword(encrypted, key, iv));
        }

        private static byte[] GenerateRandomKey()
        {
            var key = new byte[32];
            var rand = new SecureRandom();
            rand.NextBytes(key);
            return key;
        }

        private static byte[] GenerateRandomIv()
        {
            var iv = new byte[16];
            var rand = new SecureRandom();
            rand.NextBytes(iv);
            return iv;
        }

        private static byte[] EncryptPassword(string password, byte[] key, byte[] iv)
        {
            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var padding = new Pkcs7Padding();
            var cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
            var keyParam = new KeyParameter(key);
            var ivAndKeyParam = new ParametersWithIV(keyParam, iv);
            
            cipher.Init(true, ivAndKeyParam);

            var plainTextData = Encoding.UTF8.GetBytes(password);
            var cipherTextData = new byte[cipher.GetOutputSize(plainTextData.Length)];

            var length = cipher.ProcessBytes(plainTextData, 0, plainTextData.Length, cipherTextData, 0);
            cipher.DoFinal(cipherTextData, length);

            return cipherTextData;
        }

        private static string DecryptPassword(byte[] cipherText, byte[] key, byte[] iv)
        {
            var engine = new AesEngine();
            var blockCipher = new CbcBlockCipher(engine);
            var padding = new Pkcs7Padding();
            var cipher = new PaddedBufferedBlockCipher(blockCipher, padding);
            var keyParam = new KeyParameter(key);
            var ivAndKeyParam = new ParametersWithIV(keyParam, iv);
            
            cipher.Init(false, ivAndKeyParam);

            var plainTextData = new byte[cipher.GetOutputSize(cipherText.Length)];
            var length = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainTextData, 0);
            cipher.DoFinal(plainTextData, length);

            return Encoding.UTF8.GetString(plainTextData).TrimEnd('\0');
        }
    }
}