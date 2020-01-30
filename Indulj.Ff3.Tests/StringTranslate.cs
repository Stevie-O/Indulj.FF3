using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Indulj.Ff3.Tests
{
    [TestFixture]
    public class StringTranslate
    {
        [Test]
        [TestCase("9876543210", new ushort[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, })]
        [TestCase("0123456789", new ushort[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, })]
        [TestCase("++++", new ushort[] { })]
        [TestCase("++1++2++3++", new ushort[] { 1, 2, 3, })]
        [TestCase("1++2++3++4++5", new ushort[] { 1, 2, 3, 4, 5, })]
        public void TestRoundTripDigits(string s, ushort[] sequence)
        {
            const string digits = "0123456789";
            var (raw, fmt) = Ff3Helpers.DecodeString(s, digits);
            CollectionAssert.AreEqual(sequence, raw, "Decoded data mismatch");
            var result = Ff3Helpers.EncodeString(raw, digits, fmt);
            Assert.AreEqual(s, result, "Re-encoded data mismatch");
        }
    }
}
