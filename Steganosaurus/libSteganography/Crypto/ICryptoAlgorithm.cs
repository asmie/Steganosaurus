using System;
using System.Collections.Generic;
using System.Text;

namespace libSteganography.Crypto
{
    public interface ICryptoAlgorithm
    {
        byte[] EncryptText(string plain, string key);

        byte[] EncryptMemory(byte[] plain, string key);

        string DecryptText(byte[] encrypted, string key);

        byte[] DecryptMemory(byte[] encrypted, string key);

    }
}
