using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace libSteganography.Crypto
{
    public class SymmetricCrypto
    {

        public enum 

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
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("key empty or invalid size");

            using (var myAlgo = CreateInstance(Algorithm))
            {
                myAlgo.Key = Key;
                myAlgo.Mode = Mode;
                myAlgo.IV = IV;

                ICryptoTransform encryptor = myAlgo.CreateEncryptor(myAlgo.Key, myAlgo.IV);

                using var msEncrypt = new MemoryStream();
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plain, 0, plain.Length);
                    csEncrypt.Close();
                }

                encrypted = msEncrypt.ToArray();
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

            using (var myAlgo = CreateInstance(Algorithm))
            {
                myAlgo.Key = Key;
                myAlgo.Mode = Mode;
                myAlgo.IV = IV;


                ICryptoTransform decryptor = myAlgo.CreateEncryptor(myAlgo.Key, myAlgo.IV);

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

        public string Algorithm
        {
            get; set;
        } = "AES";

        public CipherMode Mode
        {
            get; set;
        } = CipherMode.CBC;

        public PaddingMode Padding
        {
            get; set;
        } = PaddingMode.PKCS7;



        public static SymmetricAlgorithm CreateInstance(string name)
        {
            foreach (Tuple<string, Type> x in _registeredAlgorithms)
            {
                if (x.Item1 == name)
                    return (SymmetricAlgorithm)Activator.CreateInstance(x.Item2);
            }

            return null;
        }

        public static bool RegisterAlgorithm(string name, Type creator)
        {
            _registeredAlgorithms.Add(new Tuple<string, Type>(name, creator));
            return true;
        }

        private static List<Tuple<string, Type>> _registeredAlgorithms = new List<Tuple<string, Type>>
                (new[] {
            new Tuple<string, Type>( "AES", typeof(AesCryptoServiceProvider)),
            new Tuple<string, Type>( "Rijandel", typeof(RijndaelManaged)),
        });

    }
}
