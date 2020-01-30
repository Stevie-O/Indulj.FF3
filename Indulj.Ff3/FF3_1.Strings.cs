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
    }
}
