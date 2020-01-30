using System;
using System.Collections.Generic;
using System.Text;

namespace Indulj.Ff3
{
    partial class FF3_1
    {
        /// <summary>
        /// Encrypts a string
        /// </summary>
        /// <param name="tweak">Optional tweak</param>
        /// <param name="value">Value</param>
        /// <param name="charset">Character set</param>
        /// <returns>The encrypted string</returns>
        public string Encrypt(byte[] tweak, string value, string charset)
        {
            var (raw, fmt) = Ff3Helpers.DecodeString(value, charset);
            Encrypt(tweak, raw, raw);
            return Ff3Helpers.EncodeString(raw, charset, fmt);
        }

        /// <summary>
        /// Decrypts a string
        /// </summary>
        /// <param name="tweak">Optional tweak</param>
        /// <param name="value">Value</param>
        /// <param name="charset">Character set</param>
        /// <returns>The encrypted string</returns>
        public string Decrypt(byte[] tweak, string value, string charset)
        {
            var (raw, fmt) = Ff3Helpers.DecodeString(value, charset);
            Decrypt(tweak, raw, raw);
            return Ff3Helpers.EncodeString(raw, charset, fmt);
        }

        ushort RadixAdd(ushort a, ushort b)
        {
            int tmp = a + b;
            if (tmp >= radix) tmp -= (int)radix;
            return (ushort)tmp;
        }

        ushort RadixSub(ushort a, ushort b)
        {
            int tmp = a - b;
            if (tmp < 0) tmp += (int)radix;
            return (ushort)tmp;
        }

        public string BpsDecrypt(byte[] tweak, string value, string charset)
        {
            var (X, fmt) = Ff3Helpers.DecodeString(value, charset);
            if (X.Length <= maxlen) {
                Decrypt(tweak, X, X);
                return Ff3Helpers.EncodeString(X, charset, fmt);
            }

            this.EnableFF3TweakSupport = true;
            if (tweak == null) tweak = new byte[8];

            var rest = X.Length % maxlen;
            var c = X.Length - rest;
            byte i = (byte)(c / maxlen);
            var Y = (ushort[])X.Clone();
            var tmp_block = new ushort[maxlen];

            if (rest > 0)
            {
                tweak[1] ^= i;
                tweak[5] ^= i;

                // there's some WTFery going on here with the incomplete final block
                // we decrypt a "full block" that overlaps the preceding block
                // this requires some finagling
                Array.Copy(Y, Y.Length - maxlen, tmp_block, 0, maxlen);
                Decrypt(tweak, tmp_block, tmp_block);
                for (int idx = 0; idx < rest; idx++)
                {
                    tmp_block[idx] = RadixSub(tmp_block[idx], Y[Y.Length - maxlen - rest]);
                }
                // because we are "double-decrypting" stuff, we need to copy back over Y as well
                tmp_block.CopyTo(Y, Y.Length - maxlen);
                tmp_block.CopyTo(X, X.Length - maxlen);

                tweak[1] ^= i;
                tweak[5] ^= i;
            }

            while (i > 0)
            {
                c -= maxlen;
                i--;
                tweak[1] ^= i;
                tweak[5] ^= i;
                Array.Copy(Y, c, tmp_block, 0, maxlen);
                if (i > 0)
                {
                    for (int idx = 0; idx < maxlen; idx++)
                    {
                        tmp_block[idx] = RadixSub(tmp_block[idx], Y[idx + c - maxlen]);
                    }
                }
                Decrypt(tweak, tmp_block, tmp_block);
                tmp_block.CopyTo(X, c);
                tweak[1] ^= i;
                tweak[5] ^= i;
            }

            return Ff3Helpers.EncodeString(X, charset, fmt);
        }
    }
}
