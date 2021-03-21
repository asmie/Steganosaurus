using System;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Text;

namespace libSteganography.Crypto
{

    public readonly struct SymmetricAlgorithmParams
    {
        public string Name { get; }
        public List<int> KeySizes { get; }
        public List<int> BlockSizes { get; }

        public SymmetricAlgorithmParams(string name, List<int> keySizes, List<int> blockSizes)
        {
            Name = name;
            KeySizes = new List<int>(keySizes);
            BlockSizes = new List<int>(blockSizes);
        }
    }

    public class AvailableSymmetricAlgorithms
    {
        public AvailableSymmetricAlgorithms()
        {
            _registeredAlgorithms = new List<SymmetricAlgorithmParams>();
            RegisterBuiltIns();
        }

        public bool RegisterAlgorithm(string name, List<int> keySizes, List<int> blockSizes)
        {
            _registeredAlgorithms.Add(new SymmetricAlgorithmParams(name, keySizes, blockSizes));
            return true;
        }


        private void RegisterBuiltIns()
        {
            foreach (SymmetricAlgorithmParams x in _symmetricAlgorythmsBuiltIns)
                RegisterAlgorithm(x.Name, x.KeySizes, x.BlockSizes);
        }


        private List<SymmetricAlgorithmParams> _registeredAlgorithms;


        private readonly ReadOnlyCollection<SymmetricAlgorithmParams> _symmetricAlgorythmsBuiltIns = new ReadOnlyCollection<SymmetricAlgorithmParams>
        (new[] {
            new SymmetricAlgorithmParams( "AES", new List<int>{128, 256 }, new List<int>{128 }),
            new SymmetricAlgorithmParams( "Rijandel", new List<int>{128, 256 }, new List<int>{128, 256 }),
        });
    }



}
