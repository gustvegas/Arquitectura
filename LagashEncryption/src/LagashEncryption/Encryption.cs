using Microsoft.Framework.ConfigurationModel;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace LagashEncryption
{
    public class Encryption
    {
        private static string _configurationKey = "encryptionKey";
        private static string _key = "F15F0948C908DBCD65E725E10D4D8D129DFE294F9A29CBB9C29CA56F978520CA";
        private static Configuration configuration = new Configuration();

        static Encryption()
        {
            configuration.AddJsonFile("C:\\Users\\gustvegas\\Documents\\GitHub\\Arquitectura\\LagashEncryption\\src\\LagashEncryption\\encryption.json");
        }

        private static string DefaultKey
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(configuration.Get(_configurationKey)))
                {
                    var key = configuration.Get(_configurationKey);

                    ValidateKey(key);

                    _key = key;
                }

                return _key;
            }
        }

        private static void ValidateKey(string key)
        {
            if (key.Length != 64 && key.Length != 48 && key.Length != 32)
                throw new Exception("No es posible iniciar la criptogrfía ya que el largo de clave no coinicide con los soportados (128bits / 192bits/ 256bits == 32chars / 48chars / 64 chars). Verifique del archivo de configuración. El largo de la clave obtenida es: \{key.Length}. La clave obtenida desde el archivo de configuración es: \{key} ");
        }

        public static string CalculateHash(string text)
        {
            using (var md5 = new System.Security.Cryptography.MD5CryptoServiceProvider())
            {
                var enc = new UTF8Encoding(false, true);
                var plainBytes = enc.GetBytes(text);
                var hashBytes = md5.ComputeHash(plainBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        public static string EncryptHexa(string text)
        {
            return Encrypt(text, true, null);
        }

        public static string DecryptHexa(string text, string key)
        {
            return Decrypt(text, true, key);
        }

        public static string DecryptHexa(string text)
        {
            return Decrypt(text, true, null);
        }

        public static string Encrypt(string text, string key)
        {
            return Encrypt(text, false, key);
        }

        public static string Encrypt(string text)
        {
            return Encrypt(text, false, null);
        }

        public static string Decrypt(string text, string key)
        {
            return Decrypt(text, false, key);
        }

        public static string Decrypt(string text)
        {
            return Decrypt(text, false, null);
        }

        private static string Encrypt(string text, bool convertToHexa, string key)
        {
            try
            {
                using (RijndaelManaged Cipher = GetCipher(key))
                {
                    ICryptoTransform trans = Cipher.CreateEncryptor();

                    Encoding enc = new UTF8Encoding(false, true);
                    byte[] plainText = enc.GetBytes(text);
                    byte[] cipherText = trans.TransformFinalBlock(plainText, 0, plainText.Length);

                    string result = convertToHexa ? ToHexa(Cipher.IV) + ToHexa(cipherText)
                        : Convert.ToBase64String(Cipher.IV) + Convert.ToBase64String(cipherText);

                    return result;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("No es posible iniciar la criptogrfía.", ex);
            }
        }

        public static byte[] Encrypt(byte[] text, string key)
        {
            try
            {
                using (RijndaelManaged Cipher = GetCipher(key))
                {
                    ICryptoTransform trans = Cipher.CreateEncryptor();

                    byte[] cypher = trans.TransformFinalBlock(text, 0, text.Length);

                    byte[] result = new byte[Cipher.IV.Length + cypher.Length];

                    Buffer.BlockCopy(Cipher.IV, 0, result, 0, Cipher.IV.Length);
                    Buffer.BlockCopy(cypher, 0, result, Cipher.IV.Length, cypher.Length);

                    return result;
                }
            }
            catch (Exception ex)
            {
                throw new Exception("No es posible iniciar la criptogrfía.", ex);
            }
        }

        public static byte[] Decrypt(byte[] cipher, string key)
        {
            try
            {
                using (RijndaelManaged Cipher = GetCipher(key))
                {
                    Cipher.IV = cipher.Take(32).ToArray();

                    byte[] cryptoBuffer = new byte[cipher.Length - 32];
                    System.Buffer.BlockCopy(cipher, 32, cryptoBuffer, 0, cipher.Length - 32);

                    ICryptoTransform trans = Cipher.CreateDecryptor();
                    return trans.TransformFinalBlock(cryptoBuffer, 0, cryptoBuffer.Length);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("No es posible iniciar la desencriptación.", ex);
            }
        }

        private static string Decrypt(string encryptedTicket, bool convertFromHexa, string key)
        {
            try
            {
                using (RijndaelManaged Cipher = GetCipher(key))
                {
                    int IVoffset;
                    byte[] cipherText;

                    if (convertFromHexa)
                    {
                        IVoffset = Cipher.IV.Length * 2;
                        Cipher.IV = FromHexa(encryptedTicket.Substring(0, IVoffset));
                        cipherText = FromHexa(encryptedTicket.Substring(IVoffset, encryptedTicket.Length - IVoffset));
                    }
                    else
                    {
                        IVoffset = (int)(Cipher.IV.Length * 1.375M);
                        Cipher.IV = Convert.FromBase64String(encryptedTicket.Substring(0, IVoffset));
                        cipherText = Convert.FromBase64String(encryptedTicket.Substring(IVoffset, encryptedTicket.Length - IVoffset));
                    }

                    ICryptoTransform trans = Cipher.CreateDecryptor();

                    byte[] plainText = trans.TransformFinalBlock(cipherText, 0, cipherText.Length);

                    Encoding enc = new UTF8Encoding(false, true);

                    return enc.GetString(plainText);
                }
            }
            catch (Exception ex)
            {
                throw new Exception("No es posible iniciar la desencriptación.", ex);
            }
        }

        private static RijndaelManaged GetCipher(string key)
        {
            RijndaelManaged cipher = new RijndaelManaged();
            cipher.KeySize = Encryption.DefaultKey.Length * 4;
            cipher.BlockSize = Encryption.DefaultKey.Length * 4;
            cipher.Mode = CipherMode.CBC;
            cipher.Padding = PaddingMode.PKCS7;

            if (!String.IsNullOrWhiteSpace(key))
            {
                ValidateKey(key);
                cipher.Key = FromHexa(key);
            }
            else
                cipher.Key = FromHexa(Encryption.DefaultKey);

            cipher.GenerateIV();
            return cipher;
        }

        private static string ToHexa(byte[] Bytes)
        {
            StringBuilder Result = new StringBuilder();
            string HexAlphabet = "0123456789ABCDEF";

            foreach (byte B in Bytes)
            {
                Result.Append(HexAlphabet[(int)(B >> 4)]);
                Result.Append(HexAlphabet[(int)(B & 0xF)]);
            }

            return Result.ToString();
        }

        private static byte[] FromHexa(string Hex)
        {
            byte[] Bytes = new byte[Hex.Length / 2];
            int[] HexValue = new int[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D,
                                 0x0E, 0x0F };

            for (int x = 0, i = 0; i < Hex.Length; i += 2, x += 1)
            {
                Bytes[x] = (byte)(HexValue[Char.ToUpper(Hex[i + 0]) - '0'] << 4 |
                                  HexValue[Char.ToUpper(Hex[i + 1]) - '0']);
            }

            return Bytes;
        }
    }
}
