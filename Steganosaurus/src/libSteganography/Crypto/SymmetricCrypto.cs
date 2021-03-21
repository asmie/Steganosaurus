using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace libSteganography.Crypto
{
    public class SymmetricCrypto
    {

        public SymmetricCrypto()
        {

        }

        public byte[] EncryptText(string plain)
        {
            return EncryptMemory(Encoding.UTF8.GetBytes(plain));
        }

        public byte[] EncryptMemory(byte[] plain)
        {
            byte[] encrypted;
           // var realKey = new Rfc2898DeriveBytes(key, Salt, 4);

            if (plain == null || plain.Length <= 0)
                throw new ArgumentNullException("plain empty");
            if (Key == null || (Key.Length != 16 && Key.Length != 32))
                throw new ArgumentNullException("key empty or invalid size");
            
            using (SymmetricAlgorithm myAes = new AesCryptoServiceProvider())
            {
                myAes.Key = Key;

                myAes.Mode = CipherMode.CBC;
                myAes.IV = new byte[16]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

                ICryptoTransform encryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(plain, 0, plain.Length);
                        csEncrypt.Close();
                    }

                    encrypted = msEncrypt.ToArray();
                }
            }

            return encrypted;
        }


        public string DecryptText(byte[] encrypted)
        {
            return Encoding.UTF8.GetString(DecryptMemory(encrypted));
        }

        public byte[] DecryptMemory(byte[] encrypted)
        {
            byte[] plain;

            if (encrypted == null || encrypted.Length <= 0)
                throw new ArgumentNullException("encrypted");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("key");

            using (var myAes = new AesCryptoServiceProvider())
            {
                myAes.Key = Key;
                myAes.Mode = CipherMode.CBC;
                myAes.IV = new byte[16] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

                ICryptoTransform decryptor = myAes.CreateEncryptor(myAes.Key, myAes.IV);

                using (var msDecrypt = new MemoryStream())
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Write))
                    {
                        csDecrypt.Write(encrypted, 0, encrypted.Length);
                        csDecrypt.Close();
                    }
                    
                    plain = msDecrypt.ToArray();
                }
            }

            return plain;
        }

        public byte[] Salt
        {
            get; set;
        } = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        public byte[] Key
        {
            private get;
            set;
        } = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        public byte[] IV
        {
            private get;
            set;
        } = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };

        public CipherMode Mode
        {
            get; set;
        } = CipherMode.CBC;

        public PaddingMode Padding
        {
            get; set;
        } = PaddingMode.PKCS7;


    }
}
