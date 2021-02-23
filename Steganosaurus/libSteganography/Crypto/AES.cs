using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace libSteganography.Crypto
{
    public class AES : ICryptoAlgorithm
    {

        public AES()
        {
            Salt = new byte[] { 0x22, 0x49, 0x19, 0xFE, 0xA7, 0x00, 0x3E, 0xBB, 0x10, 0x37 };
        }

        public byte[] EncryptText(string plain, string key)
        {
            return EncryptMemory(Encoding.UTF8.GetBytes(plain), key);
        }

        public byte[] EncryptMemory(byte[] plain, string key)
        {
            byte[] encrypted;
            var realKey = new Rfc2898DeriveBytes(key, Salt);

            if (plain == null || plain.Length <= 0)
                throw new ArgumentNullException("plain");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");

            using (var myAes = new AesCryptoServiceProvider())
            {
                myAes.Key = realKey.GetBytes(16);
                myAes.Mode = CipherMode.CBC;
                myAes.IV = new byte[16]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

                ICryptoTransform encryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plain);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }


        public string DecryptText(byte[] encrypted, string key)
        {
            return Encoding.UTF8.GetString(DecryptMemory(encrypted, key));
        }

        public byte[] DecryptMemory(byte[] encrypted, string key)
        {
            byte[] plain;
            var realKey = new Rfc2898DeriveBytes(key, Salt);

            if (encrypted == null || encrypted.Length <= 0)
                throw new ArgumentNullException("encrypted");
            if (key == null || key.Length <= 0)
                throw new ArgumentNullException("key");

            using (var myAes = new AesCryptoServiceProvider())
            {
                myAes.Key = realKey.GetBytes(16);
                myAes.Mode = CipherMode.CBC;
                myAes.IV = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                ICryptoTransform decryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (var msDecrypt = new MemoryStream())
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csDecrypt))
                        {
                            swEncrypt.Write(encrypted);
                        }
                        plain = msDecrypt.ToArray();
                    }
                }
            }

            return plain;
        }


        public byte[] Salt
        {
            get; set;
        }
    }
}
