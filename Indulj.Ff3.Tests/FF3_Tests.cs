using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace Indulj.Ff3.Tests
{
    [TestFixture]
    public class FF3_Tests
    {
        [TestCaseSource(nameof(NistSamples))]
        public void Encrypt(NistFf3Sample sample)
        {
            TestEncryption(sample);
        }

        [TestCaseSource(nameof(NistSamples))]
        public void Decrypt(NistFf3Sample sample)
        {
            TestDecryption(sample);
        }

        const string DECIMAL_DIGITS = "0123456789";
        const string HEXADUODECIMAL_DIGITS = "0123456789abcdefghijklmnop";

        public static IEnumerable<TestCaseData> NistSamples =>
                samples.Select(s => new TestCaseData(s) { TestName = "{m} " + s.SampleId });

        public static NistFf3Sample[] samples = new[] {
new NistFf3Sample("Sample #1", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", "D8 E7 92 0A FA 33 0A 73", "0123456789", "890121234567890000", "750918814058654607"),
new NistFf3Sample("Sample #2", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", "9A 76 8A 92 F6 0E 12 D8", "0123456789", "890121234567890000", "018989839189395384"),
new NistFf3Sample("Sample #3", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", "D8 E7 92 0A FA 33 0A 73", "0123456789", "89012123456789000000789000000", "48598367162252569629397416226"),
new NistFf3Sample("Sample #4", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", "00 00 00 00 00 00 00 00", "0123456789", "89012123456789000000789000000", "34695224821734535122613701434"),
new NistFf3Sample("Sample #5", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94", "9A 76 8A 92 F6 0E 12 D8", "0123456789abcdefghijklmnop", "0123456789abcdefghi", "g2pk40i992fn20cjakb"),
new NistFf3Sample("Sample #6", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6", "D8 E7 92 0A FA 33 0A 73", "0123456789", "890121234567890000", "646965393875028755"),
new NistFf3Sample("Sample #7", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6", "9A 76 8A 92 F6 0E 12 D8", "0123456789", "890121234567890000", "961610514491424446"),
new NistFf3Sample("Sample #8", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6", "D8 E7 92 0A FA 33 0A 73", "0123456789", "89012123456789000000789000000", "53048884065350204541786380807"),
new NistFf3Sample("Sample #9", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6", "00 00 00 00 00 00 00 00", "0123456789", "89012123456789000000789000000", "98083802678820389295041483512"),
new NistFf3Sample("Sample #10", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6", "9A 76 8A 92 F6 0E 12 D8", "0123456789abcdefghijklmnop", "0123456789abcdefghi", "i0ihe2jfj7a9opf9p88"),
new NistFf3Sample("Sample #11", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", "D8 E7 92 0A FA 33 0A 73", "0123456789", "890121234567890000", "922011205562777495"),
new NistFf3Sample("Sample #12", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", "9A 76 8A 92 F6 0E 12 D8", "0123456789", "890121234567890000", "504149865578056140"),
new NistFf3Sample("Sample #13", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", "D8 E7 92 0A FA 33 0A 73", "0123456789", "89012123456789000000789000000", "04344343235792599165734622699"),
new NistFf3Sample("Sample #14", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", "00 00 00 00 00 00 00 00", "0123456789", "89012123456789000000789000000", "30859239999374053872365555822"),
new NistFf3Sample("Sample #15", "EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94 2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C", "9A 76 8A 92 F6 0E 12 D8", "0123456789abcdefghijklmnop", "0123456789abcdefghi", "p0b2godfja9bhb7bk38"),
};

        public struct NistFf3Sample
        {
            public readonly string SampleId;
            public readonly string Key;
            public readonly string Tweak;
            public readonly string CharacterSet;
            public readonly string Plaintext;
            public readonly string ExpectedCiphertext;
            public NistFf3Sample(string sampleId, string key, string tweak, string characterSet, string plaintext, string expectedCiphertext)
            {
                SampleId = sampleId;
                Key = key;
                Tweak = tweak;
                CharacterSet = characterSet;
                Plaintext = plaintext;
                ExpectedCiphertext = expectedCiphertext;
            }
        }


        void TestSample4()
        {
            // Sample 4
            FF3Test("EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94",
                "D8 E7 92 0A FA 33 0A 73",
                "0123456789",
                "89012123456789000000789000000",
                CipherOperation.Encrypt
                );
            FF3Test("EF 43 59 D8 D5 80 AA 4F 7F 03 6D 6F 04 FC 6A 94",
                    "D8 E7 92 0A FA 33 0A 73",
                    "0123456789",
                    "48598367162252569629397416226",
                    CipherOperation.Decrypt
                    );
        }

        enum CipherOperation { Encrypt, Decrypt, }

        static byte[] DecodeHex(string str)
        {
            return str.Split(' ').Select(s => byte.Parse(s, System.Globalization.NumberStyles.HexNumber)).ToArray();
        }

        static T Clone<T>(T src) where T : ICloneable
        {
            if (src == null) return default(T);
            return (T)src.Clone();
        }

        static void TestEncryption(NistFf3Sample sample)
        {
            var result = FF3Test(sample.Key, sample.Tweak, sample.CharacterSet, sample.Plaintext, CipherOperation.Encrypt);
            Assert.AreEqual(sample.ExpectedCiphertext, result, "Ciphertext mismatch");
        }

        static void TestDecryption(NistFf3Sample sample)
        {
            var result = FF3Test(sample.Key, sample.Tweak, sample.CharacterSet, sample.ExpectedCiphertext, CipherOperation.Decrypt);
            Assert.AreEqual(sample.Plaintext, result, "Plaintext mismatch");
        }

        static string FF3Test(string keyHex, string tweakHex, string charset, string plaintext, CipherOperation operation)
        {
            var keyBytes = DecodeHex(keyHex);
            var tweakBytes = DecodeHex(tweakHex);
            var ptSymbols = plaintext.Select(ch => (ushort)charset.IndexOf(ch)).ToArray();
            FF3_1.Reverse(keyBytes);
            using (var cipher = new RijndaelManaged() { Key = keyBytes, BlockSize = 128, })
            {
                var ff3 = new FF3_1(cipher, charset.Length, 6, 29);
                ff3.EnableFF3TweakSupport = true;
                var ptSymbolsInput = Clone(ptSymbols);
                var ctSymbols = ptSymbolsInput;
                /*
                var ctSymbols = (operation == CipherOperation.Encrypt)
                        ? ff3.Encrypt(tweakBytes, ptSymbolsInput)
                        : ff3.Decrypt(tweakBytes, ptSymbolsInput)
                        ;
                    */
                if (operation == CipherOperation.Encrypt)
                    ff3.Encrypt(tweakBytes, ctSymbols);
                else
                    ff3.Decrypt(tweakBytes, ctSymbols);
                var ct = string.Join("", ctSymbols.Select(sym => charset[sym]));
                //ct.Dump("CT");
                return ct;
            }
        }

    }
}
