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
        /// <returns>The decrypted string</returns>
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

        /// <summary>
        /// Encrypts a string according to Algorithm 3 of the original BPS whitepaper.
        /// </summary>
        /// <param name="tweak">Optional tweak. NOTE that the contents of this array are modified during execution.</param>
        /// <param name="value">Value</param>
        /// <param name="charset">Character set</param>
        /// <returns>The encrypted string</returns>
        /// <remarks>
        /// For input strings that are not longer than the "maxlen" property passed to the constructor, this method is equivalent to <see cref="Encrypt(byte[], string, string)"/>.
        /// For longer strings, this follows the weird CBC-like process described in the original BPS whitepaper, which was _not_ brought into the NIST FF3 standard.
        /// </remarks>
        public string BpsEncrypt(byte[] tweak, string value, string charset)
        {
            var (X, fmt) = Ff3Helpers.DecodeString(value, charset);
            if (X.Length <= maxlen)
            {
                Encrypt(tweak, X, X);
                return Ff3Helpers.EncodeString(X, charset, fmt);
            }

            this.EnableFF3TweakSupport = true;
            if (tweak == null) tweak = new byte[8];

            int c = 0;
            var Y = (ushort[])X.Clone();
            var tmp_block = new ushort[maxlen];
            byte i;

            for (i = 0; c + maxlen < X.Length; i++)
            {
                tweak[1] ^= i;
                tweak[5] ^= i;
                Array.Copy(Y, c, tmp_block, 0, maxlen);
                if (i > 0)
                {
                    for (int idx = 0; idx < maxlen; idx++)
                    {
                        tmp_block[idx] = RadixAdd(tmp_block[idx], Y[idx + c - maxlen]);
                    }
                }
                Encrypt(tweak, tmp_block, tmp_block);
                tmp_block.CopyTo(Y, c);
                tweak[1] ^= i;
                tweak[5] ^= i;

                c += maxlen;
            }

            if (c < X.Length)
            {
                var rest = X.Length - c;

                tweak[1] ^= i;
                tweak[5] ^= i;

                // there's some WTFery going on here with the incomplete final block
                for (int idx = X.Length - rest; idx < X.Length; idx++)
                    Y[idx] = RadixAdd(Y[idx], Y[idx - maxlen]);

                Array.Copy(Y, Y.Length - maxlen, tmp_block, 0, maxlen);
                Encrypt(tweak, tmp_block, tmp_block);
                tmp_block.CopyTo(Y, Y.Length - maxlen);

                tweak[1] ^= i;
                tweak[5] ^= i;
            }

            return Ff3Helpers.EncodeString(Y, charset, fmt);
        }

        /// <summary>
        /// Decrypts a string according to Algorithm 4 of the original BPS whitepaper.
        /// </summary>
        /// <param name="tweak">Optional tweak. NOTE that the contents of this array are modified during execution.</param>
        /// <param name="value">Value</param>
        /// <param name="charset">Character set</param>
        /// <returns>The decrypted string</returns>
        /// <remarks>
        /// For input strings that are not longer than the "maxlen" property passed to the constructor, this method is equivalent to <see cref="Decrypt(byte[], string, string)"/>.
        /// For longer strings, this follows the weird CBC-like process described in the original BPS whitepaper, which was _not_ brought into the NIST FF3 standard.
        /// </remarks>
        public string BpsDecrypt(byte[] tweak, string value, string charset)
        {
            var (X, fmt) = Ff3Helpers.DecodeString(value, charset);
            if (X.Length <= maxlen)
            {
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
                // oh this is nuts
                for (int idx = 1; idx <= rest; idx++)
                {
                    tmp_block[tmp_block.Length - idx] = RadixSub(tmp_block[tmp_block.Length - idx], Y[ Y.Length - idx - maxlen]);
                }
                // because we are "double-decrypting" stuff, we need to copy back over Y as well
                tmp_block.CopyTo(Y, Y.Length - maxlen);

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
                tmp_block.CopyTo(Y, c);
                tweak[1] ^= i;
                tweak[5] ^= i;
            }

            return Ff3Helpers.EncodeString(Y, charset, fmt);
        }
    }
}
