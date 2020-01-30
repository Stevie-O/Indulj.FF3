using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Indulj.Ff3.Tests
{
    [TestFixture]
    public class BpsTests
    {
        [Test]
        public void Bps1()
        {

            var cipher = new TripleDESCryptoServiceProvider();
            var ff3 = new FF3_1(cipher, 10, 15, 18);

            ff3.BpsDecrypt(null, "240879490670447=16865044234484857068", "0123456789");

        }
    }
}
