using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Indulj.Ff3.Tests
{
    /// <summary>
    /// I used this stuff to debug the BpsEncrypt and BpsDecrypt code
    /// turns out there were a bunch of bugs in the TDES compatibility logic
    /// </summary>
    [TestFixture]
    public class BpsTests
    {
        [Test]
        public void BpsEncrypt()
        {
            var cipher = new TripleDESCryptoServiceProvider();
            var ff3 = new FF3_1(cipher, 10);

            cipher.Key = decodeHex("218404a1f3e37dbd22f381d6496c0c76");

            const string pt = "031085877575534=071010041185624028500";
            const string ct = "230579562312061=389554388516046393189";

            var result = ff3.BpsEncrypt(null, pt.Substring(1), "0123456789");
            Assert.That(result, Is.EqualTo(ct.Substring(1)));
        }

        [Test]
        public void BpsDecrypt()
        {
            var cipher = new TripleDESCryptoServiceProvider();
            var ff3 = new FF3_1(cipher, 10);

            cipher.Key = decodeHex("218404a1f3e37dbd22f381d6496c0c76");

            const string pt = "031085877575534=071010041185624028500";
            const string ct = "230579562312061=389554388516046393189";

            var result = ff3.BpsDecrypt(null, ct.Substring(1), "0123456789");
            Assert.That(result, Is.EqualTo(pt.Substring(1)));
        }

        [Test]
        public void Bps1()
        {
            var cipher = new TripleDESCryptoServiceProvider();
            var ff3 = new FF3_1(cipher, 10);

            cipher.Key = decodeHex("218404a1f3e37dbd22f381d6496c0c76");

            var result = ff3.BpsEncrypt(null, "031085877575534=071010041185624028500".Substring(1), "0123456789");
            Assert.That(result, Is.EqualTo("230579562312061=389554388516046393189".Substring(1)));
        }

        static byte[] decodeHex(string s)
        {
            var buf = new byte[s.Length / 2];
            for (int i = 0; i < s.Length; i += 2)
                buf[i / 2] = byte.Parse(s.Substring(i, 2), NumberStyles.HexNumber);
            return buf;
        }

        [Test]
        public void ThatsWeird()
        {

            var bpsKey = decodeHex("218404a1f3e37dbd22f381d6496c0c76");

            var ff3 = new FF3_1(
            new TripleDESCryptoServiceProvider() { Key = /* FF3_1.ReverseKey(bpsKey) */ bpsKey },
            10);

            ff3.EnableFF3TweakSupport = true;

            ff3.Encrypt(null, "31085877575534071010041185624028500".Substring(0, 18), "0123456789");

        }
    }
}
