using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace EnvoyeSpecialDecryptor
{
    class Decryptor
    {
        public string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        public byte[] GetProtectorStaticKey()
        {
            byte[] bytes2 = Encoding.UTF8.GetBytes("g!5c648t9d5NLtT36H5ef;V,:]6Yp4;ximPfD>*648t9d5NLtTMe4!5c36H5ef;V,:]6Yp4+<8B##CJ648t9d5NLtT");
            bytes2 = SHA256.Create().ComputeHash(bytes2);
            System.Console.WriteLine("Protector key: {0}", ByteArrayToString(bytes2));
            return bytes2;
        }

        public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
            byte[] result = null;
            byte[] salt = new byte[8] { 1, 2, 3, 4, 5, 6, 7, 8 };
            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (RijndaelManaged rijndaelManaged = new RijndaelManaged())
                {
                    rijndaelManaged.KeySize = 256;
                    rijndaelManaged.BlockSize = 128;
                    Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(passwordBytes, salt, 1000);
                    rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
                    rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
                    rijndaelManaged.Mode = CipherMode.CBC;
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                        cryptoStream.Close();
                    }
                    result = memoryStream.ToArray();
                }
            }
            return result;
        }

        public bool FileDecryptor(string file, byte[] key)
        {
            byte[] encryptedData = File.ReadAllBytes(file);
            byte[] decryptedData = AES_Decrypt(encryptedData, key);

            if (decryptedData.Length < 256)
            {
                Console.WriteLine("Invalid file content, skipping...");
                return false;
            }

            byte[] originalFileName = new byte[256];
            Array.ConstrainedCopy(decryptedData, decryptedData.Length - 256, originalFileName, 0, 256);

            byte[] originalFileContent = new byte[decryptedData.Length - 256];
            Array.ConstrainedCopy(decryptedData, 0, originalFileContent, 0, decryptedData.Length - 256);

            char[] invalidChar = { '\x00' };
            string txtOriginalFileName = Encoding.UTF8.GetString(originalFileName).TrimEnd(invalidChar);
            Console.WriteLine("Original file name: {0}", txtOriginalFileName);

            File.WriteAllBytes(txtOriginalFileName, originalFileContent);

            return true;
        }
    }

    class Program
    {

        static int Main(string[] args)
        {
            Decryptor d = new Decryptor();

            string masterKeyfile = "windowsdefender.bin";
            byte[] encryptedMasterKey;
            try
            {
                encryptedMasterKey = File.ReadAllBytes(masterKeyfile);
            }
            catch
            {
                Console.WriteLine("Master key file ({0}) must be present in current directory.", masterKeyfile);
                return -1;
            }

            byte[] masterKey = d.AES_Decrypt(encryptedMasterKey, d.GetProtectorStaticKey());

            string txtMasterKey = Encoding.UTF8.GetString(masterKey);
            Regex r = new Regex("[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4}");
            Match m = r.Match(txtMasterKey);
            if (m.Success)
            {
                Console.WriteLine("Decrypted master key: {0}", txtMasterKey);
            }
            else
            {
                Console.WriteLine("Failed to decrypt master key");
                return -1;
            }

            if (args.Length != 1)
            {
                Console.WriteLine("Usage: Program.exe <file_to_decrypt.lockon>");
                return -1;
            }

            try
            {
                d.FileDecryptor(args[0], SHA256.Create().ComputeHash(masterKey));
            }
            catch
            {
                Console.WriteLine("Something went wrong, does the target file exist?");
                return -1;
            }

            return 0;
        }
    }
}
