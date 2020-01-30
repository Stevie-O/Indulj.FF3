using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

[assembly: InternalsVisibleTo("Indulj.Ff3.Tests")]

namespace Indulj.Ff3
{
    /// <summary>
    /// FF3-1 implementation (NIST SP 800-38G Rev. 1 Draft)
    /// </summary>
    /// <remarks>
    /// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
    /// </remarks>
    public partial class FF3_1
    {
        // NIST SP 800-38G Revision 1 Draft
        readonly uint radix;
        readonly int minlen, maxlen;
        SymmetricAlgorithm ciph;

        const int MIN_RADIX = 2;
        const int MAX_RADIX = 65536;

        /// <summary>
        /// Constructs a new instance of an FF3-1 encryptor/decryptor
        /// </summary>
        /// <param name="ciph">The block-mode <see cref="SymmetricAlgorithm"/> with 128 bit blocks that is used for the Feistel round function.
        /// </param>
        /// <param name="radix">Number of characters in the character set</param>
        /// <param name="minlen">Minimum plaintext length</param>
        /// <param name="maxlen">Maximum plaintext length</param>
        /// <exception cref="ArgumentNullException"><paramref name="ciph"/> is null.</exception>
        /// <exception cref="ArgumentOutOfRangeException"><paramref name="radix"/> is not valid (minimum 2, maximum 65536).</exception>
        /// <exception cref="ArgumentException"><paramref name="ciph"/>'s <see cref="SymmetricAlgorithm.BlockSize"/> is not equal to 128.</exception>
        /// <exception cref="ArgumentException"><paramref name="minlen"/> is too small for the specified <paramref name="radix"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="minlen"/> is greater than <paramref name="maxlen"/>.</exception>
        /// <exception cref="ArgumentException"><paramref name="maxlen"/> is too large for the specified <paramref name="radix"/>.</exception>
        public FF3_1(SymmetricAlgorithm ciph, int radix, int minlen, int maxlen)
        {
            if (ciph == null) throw new ArgumentNullException(nameof(ciph));
            if (ciph.BlockSize > 128) throw new ArgumentException("Underlying cipher block size must be 128 bits");
            if (radix < MIN_RADIX || radix > MAX_RADIX) throw new ArgumentOutOfRangeException(nameof(radix), radix, "Invalid radix");
            if (minlen < 2 || minlen > maxlen) throw new ArgumentException(nameof(minlen) + " must be greater than or equal to 2, and less than or equal to " + nameof(maxlen));
            var f_bits = (ciph.BlockSize - 32);
            if (maxlen > 2 * Math.Floor(f_bits * Math.Log(2, radix)))
                throw new ArgumentException(nameof(maxlen) + " is too large for the given radix", nameof(maxlen));
            if (Math.Pow(radix, minlen) < 1e6)
                throw new ArgumentException(nameof(minlen) + " is too small", nameof(minlen));

            this.radix = (uint)radix;
            this.minlen = minlen;
            this.maxlen = maxlen;
            this.ciph = ciph;
        }

        static int bits_required(int radix, int digits)
        {
            if (radix == 0 || digits == 0) return 0;
            // computes ceil(digits * log2(radix))
            // http://forums.xkcd.com/viewtopic.php?t=74871&p=2768810
            // The above post gives me a clue: consider integers p and q, such that p is the smallest integer satisfying the inequality 2**p >= radix ** q

            // According to Wikipedia's "Binary logarithm" article:
            // floor(log2(n)) == ceil(log2(n+1))-1, if n >= 1
            // floor(log2(n)) + 1 == ceil(log2(n+1)), if n >= 1
            // Therefore, if I can compute floor(log2(radix ** digits - 1)) + 1, I will know ceil(log2(radix ** digits))
            //
            // Furthermore, unless radix is a power of 2, it is impossible for radix ** digits to be a power of 2, which means that I really just need
            // floor(log2(radix ** digits)) + 1


            // Ugh. I don't know how to do this.
            return (int)Math.Ceiling(digits * Math.Log(radix, 2));
        }

        const int FF3_1_MAX_TWEAK_SIZE = 56 / 8;
        const int FF3_LEGACY_TWEAK_SIZE = 64 / 8;

        static byte[] CreateTL(byte[] T)
        {
            if (T != null && T.Length == FF3_LEGACY_TWEAK_SIZE) return CreateTL_FF3(T);
            return CreateTL_FF3_1(T);
        }

        static byte[] CreateTR(byte[] T)
        {
            if (T != null && T.Length == FF3_LEGACY_TWEAK_SIZE) return CreateTR_FF3(T);
            return CreateTR_FF3_1(T);
        }

        static byte[] CreateTL_FF3(byte[] T)
        {
            var TL = new byte[4];
            if (T == null) return TL;
            Array.Copy(T, 0, TL, 0, 4);
            return TL;
        }

        static byte[] CreateTR_FF3(byte[] T)
        {
            var TR = new byte[4];
            if (T == null) return TR;
            Array.Copy(T, 4, TR, 0, 4);
            return TR;
        }

        static byte[] CreateTL_FF3_1(byte[] T)
        {
            var TL = new byte[4];
            if (T == null) return TL;
            TL[0] = T[0]; // 0-7
            TL[1] = T[1]; // 8-15
            TL[2] = T[2]; // 16-23
            TL[3] = (byte)(T[3] & 0xF0); // 24-27, '0000'
            return TL;
        }

        static byte[] CreateTR_FF3_1(byte[] T)
        {
            var TR = new byte[4];
            if (T == null) return TR;
            TR[0] = T[4]; // 32-39
            TR[1] = T[5]; // 40-47
            TR[2] = T[6]; // 48-55
            TR[3] = (byte)(T[3] << 4); // 28-31, '0000'
            return TR;
        }

        const int FF3_1_NUM_ROUNDS = 8;

        readonly struct Ff3Divisor : IFormattable
        {
            public readonly Ff3Accumulator ShiftedDivisor;
            public readonly Ff3Accumulator Value;
            public readonly int ShiftCount;
            public Ff3Divisor(Ff3Accumulator n)
            {
                Value = n;
                int lz = n.CountLeadingZeroes();
                ShiftedDivisor = n << lz;
                ShiftCount = lz;
            }

            public override string ToString()
            {
                return ToString(null, null);
            }

            public string ToString(string format, IFormatProvider formatProvider)
            {
                return string.Concat(
                    "<Value = ", Value.ToString(format, formatProvider),
                    ", ShiftCount = ", ShiftCount.ToString(),
                    ", ShiftedDivisor = ", ShiftedDivisor.ToString(format, formatProvider),
                    ">");
            }
        }

        internal static object TestSubtraction()
        {
            var tmp1 = new FF3_1.Ff3DivisionAccumulator(0u, 0u, 2u, 0u);
            //var tmp2 = new FF3_1.Ff3DivisionAccumulator(0u, 0u, 1u, 0xFFFFFFFFu);
            var tmp2 = new FF3_1.Ff3DivisionAccumulator(0u, 0u, 0u, 0xFFFFFFFFu);
            tmp1.Sub(tmp2);
            return tmp1;
        }

        readonly struct Ff3Accumulator : IFormattable
        {
            public readonly uint Low;
            public readonly uint Mid;
            public readonly uint High;

            public override string ToString() => $"0x{High:x8}`{Mid:x8}`{Low:x8}";

            string ToStringDecimal()
            {
                var div = new Ff3Accumulator(1_000_000_000);
                List<string> lst = new List<string>();
                var n = this;
                if (n.IsZero) return "0";
                while (!n.IsZero)
                {
                    var (q, r) = n.DivRem(div);
                    lst.Add(r.Low.ToString());
                    n = q;
                }
                for (var i = 1; i < lst.Count - 1; i++)
                {
                    lst[i] = lst[i].PadLeft(9, '0');
                }
                lst.Reverse();
                return string.Join("", lst);
            }

            public string ToString(string format, IFormatProvider formatProvider)
            {
                if (format == "D") return ToStringDecimal();
                return ToString();
            }

            public const int BIT_SIZE = 96;

            internal Ff3Accumulator(uint high, uint mid, uint low) { High = high; Mid = mid; Low = low; }

            public Ff3Accumulator(uint value) : this(0u, 0u, value) { }

            public static Ff3Accumulator CreateExponent(uint radix, uint exponent)
            {
                var f = One;
                for (uint i = 0; i < exponent; i++)
                    f = f.MultiplyAdd(radix, 0);
                return f;
            }

            public static Ff3Accumulator Zero => new Ff3Accumulator();
            public static Ff3Accumulator One => new Ff3Accumulator(0, 0, 1);
            public static Ff3Accumulator Two => new Ff3Accumulator(0, 0, 2);

            public static Ff3Accumulator operator +(Ff3Accumulator a, Ff3Accumulator b)
            {
                uint carry = 0;
                uint newLow, newMid, newHigh;
                (newLow, carry) = adc(a.Low, b.Low, carry);
                (newMid, carry) = adc(a.Mid, b.Mid, carry);
                (newHigh, carry) = adc(a.High, b.High, carry);
                if (carry != 0) throw new OverflowException();
                return new Ff3Accumulator(newHigh, newMid, newLow);
            }

            static int CountLeadingZeroes(uint x)
            {
                int n = 0;
                if (x <= 0x0000ffff) { n += 16; x <<= 16; }
                if (x <= 0x00ffffff) { n += 8; x <<= 8; }
                if (x <= 0x0fffffff) { n += 4; x <<= 4; }
                if (x <= 0x3fffffff) { n += 2; x <<= 2; }
                if (x <= 0x7fffffff) { n++; }
                return n;
            }

            public int CountLeadingZeroes()
            {
                if (High != 0) return CountLeadingZeroes(High);
                if (Mid != 0) return CountLeadingZeroes(Mid) + 32;
                if (Low != 0) return CountLeadingZeroes(Low) + 64;
                return BIT_SIZE;
            }

            public static bool operator <=(Ff3Accumulator a, Ff3Accumulator b)
            {
                if (a.High > b.High) return false;
                if (a.High < b.High) return true;

                if (a.Mid > b.Mid) return false;
                if (a.Mid < b.Mid) return true;

                if (a.Low > b.Low) return false;
                if (a.Low < b.Low) return true;

                // equal
                return true;
            }

            public static bool operator >=(Ff3Accumulator a, Ff3Accumulator b)
            {
                return b <= a;
            }

            public Ff3Accumulator Shl(int bits) => this << bits;

            public static Ff3Accumulator operator <<(Ff3Accumulator n, int bits)
            {
                // super-proper C# rules, but that's not going to happen here
                if (bits >= BIT_SIZE) bits %= BIT_SIZE;
                if (bits >= 64) { n = new Ff3Accumulator(n.Low, 0u, 0u); bits -= 64; }
                else if (bits >= 32) { n = new Ff3Accumulator(n.Mid, n.Low, 0u); bits -= 32; }
                if (bits == 0) return n;

                int rbits = 32 - bits;
                uint carry = 0;
                var newLow = (n.Low << bits) | carry;
                carry = n.Low >> rbits;
                var newMid = (n.Mid << bits) | carry;
                carry = n.Mid >> rbits;
                var newHigh = (n.High << bits) | carry;
                carry = n.High >> rbits;
                if (carry != 0) throw new OverflowException();
                return new Ff3Accumulator(newHigh, newMid, newLow);
            }

            public static Ff3Accumulator operator >>(Ff3Accumulator n, int bits)
            {
                // super-proper C# rules, but that's not going to happen here
                if (bits >= BIT_SIZE) bits %= BIT_SIZE;
                if (bits >= 64) { n = new Ff3Accumulator(0u, 0u, n.High); bits -= 64; }
                else if (bits >= 32) { n = new Ff3Accumulator(0, n.High, n.Mid); bits -= 32; }
                if (bits == 0) return n;

                int rbits = 32 - bits;
                uint carry = 0;
                var newHigh = (n.High >> bits) | carry;
                carry = (n.High << rbits);
                var newMid = (n.Mid >> bits) | carry;
                carry = (n.Mid << rbits);
                var newLow = (n.Low >> bits) | carry;
                return new Ff3Accumulator(newHigh, newMid, newLow);
            }

            public static Ff3Accumulator operator -(Ff3Accumulator a, Ff3Accumulator b)
            {
                uint carry = 0;
                uint newLow, newMid, newHigh;
                // order must go Low-Mid-High or the subtraction doesn't carry/borrow correctly
                (newLow, carry) = sbc(a.Low, b.Low, carry);
                (newMid, carry) = sbc(a.Mid, b.Mid, carry);
                (newHigh, carry) = sbc(a.High, b.High, carry);

                if (carry != 0) throw new OverflowException();
                return new Ff3Accumulator(newHigh, newMid, newLow);
            }

            public static Ff3Accumulator operator %(Ff3Accumulator n, Ff3Divisor d)
            {
                var d_shift = d.ShiftedDivisor;
                for (int i = 0; i <= d.ShiftCount; i++)
                {
                    if (n >= d_shift)
                        n -= d_shift;
                    d_shift >>= 1;
                }
                return n;
            }

            public static Ff3Accumulator operator |(Ff3Accumulator a, Ff3Accumulator b)
            {
                return new Ff3Accumulator(a.High | b.High, a.Mid | b.Mid, a.Low | b.Low);
            }

            public bool IsZero => (High == 0 && Mid == 0 && Low == 0);

            public (Ff3Accumulator q, Ff3Accumulator r) DivRem(Ff3Accumulator d) => DivRem(this, d);

            public static (Ff3Accumulator q, Ff3Accumulator r) DivRem(Ff3Accumulator n, Ff3Accumulator d)
            {
                int lz = n.CountLeadingZeroes();
                int dlz = d.CountLeadingZeroes();
                var shiftCount = dlz - lz;
                if (shiftCount < 0) return (Zero, n); // d > this (unlikely)
                if (shiftCount > 0) d <<= shiftCount;
                var q = Zero;
                var shiftMultiplier = One << shiftCount;
                for (var i = 0; i <= shiftCount; i++)
                {
                    if (n >= d)
                    {
                        n -= d;
                        q |= shiftMultiplier;
                    }
                    shiftMultiplier >>= 1;
                    d >>= 1;
                }
                return (q, n);
            }

            // Compute (this * a + b)
            public Ff3Accumulator MultiplyAdd(ulong a, uint b)
            {
                var carry = b;
                ulong tmp = Low * a + carry;
                var newLow = (uint)tmp;
                carry = (uint)(tmp >> 32);
                tmp = Mid * a + carry;
                var newMid = (uint)tmp;
                carry = (uint)(tmp >> 32);
                tmp = High * a + carry;
                var newHigh = (uint)tmp;
                carry = (uint)(tmp >> 32);
                if (carry != 0) throw new OverflowException();
                return new Ff3Accumulator(newHigh, newMid, newLow);
            }
            static void CopyTo(byte[] dest, uint value, int offset)
            {
                dest[offset] = (byte)(value >> 24);
                dest[offset + 1] = (byte)(value >> 16);
                dest[offset + 2] = (byte)(value >> 8);
                dest[offset + 3] = (byte)(value);
            }
            public void CopyTo(byte[] dest, int offset)
            {
                if (dest.Length - offset >= 12)
                {
                    CopyTo(dest, High, offset);
                    CopyTo(dest, Mid, offset + 4);
                }
                else
                {
                    if (High != 0 || Mid != 0) throw new OverflowException();
                }
                CopyTo(dest, Low, offset + 8);
            }
        }

        static uint ExtractUint(byte[] b, int offset)
        {
            return (uint)((b[offset] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]);
        }

        static (uint answer, uint carry) adc(uint a, uint b, uint carry)
        {
            ulong result = (ulong)a + (ulong)b + (ulong)carry;
            var result_value = (uint)result;
            var carry_value = (uint)(result >> 32);
            return (result_value, carry_value);
        }

        // given that carry is 0 or 1, computes a - b - carry, and the new value of carry/borrow
        static (uint answer, uint carry) sbc(uint a, uint b, uint carry)
        {
            ulong result = (ulong)((long)a - (long)b - (long)carry);
            var result_value = (uint)result;
            var carry_value = (uint)(-(int)(result >> 32));
            return (result_value, carry_value);
        }

        // 128-bit version used for ONE FREAKING STEP in this algorithm (4.iv)
        struct Ff3DivisionAccumulator : IDisposable
        {
            readonly uint[] x;

            public void Dispose() { Array.Clear(x, 0, x.Length); }

            public override string ToString()
            {
                var sb = new StringBuilder();
                var x = this.x;
                for (int i = 0; i < 4; i++)
                {
                    if (i > 0) sb.Append('`');
                    else sb.Append("0x");
                    sb.Append(x[i].ToString("x8"));
                }
                return sb.ToString();
            }

            public Ff3DivisionAccumulator(uint a, uint b, uint c, uint d)
            {
                x = new[] { a, b, c, d };
            }
            public void Shr()
            {
                uint carry = 0;
                for (var i = 0; i < 4; i++)
                {
                    var newCarry = (x[i] << 31);
                    x[i] = (x[i] >> 1) | carry;
                    carry = newCarry;
                }
            }
            public void Sub(Ff3DivisionAccumulator subtrahend)
            {
                uint carry = 0;
                /* attempts 1 and 2 go the wrong direction
                for (var i = 0; i < 4; i++)
                {
                    (x[i], carry) = sbc(x[i], subtrahend.x[i], carry);
                    // d'oh, what was I thinking here
                    //x[i] -= subtrahend.x[i];
                }*/
                for (var i = 3; i >= 0; i--)
                {
                    (x[i], carry) = sbc(x[i], subtrahend.x[i], carry);
                }
            }
            public static bool operator <=(Ff3DivisionAccumulator a, Ff3DivisionAccumulator b)
            {
                for (int i = 0; i < 4; i++)
                {
                    var a_i = a.x[i];
                    var b_i = b.x[i];
                    if (a_i > b_i) return false;
                    if (a_i < b_i) return true;
                }
                // they are equal
                return true;
            }
            public static bool operator >=(Ff3DivisionAccumulator a, Ff3DivisionAccumulator b)
            {
                return b <= a;
            }
            public Ff3Accumulator To96Bit()
            {
                if (x[0] != 0) throw new OverflowException();
                return new Ff3Accumulator(x[1], x[2], x[3]);
            }
        }

        static Ff3Accumulator Num(byte[] x, Ff3Divisor modulus)
        {
            var n = new Ff3DivisionAccumulator(
                ExtractUint(x, 0),
                ExtractUint(x, 4),
                ExtractUint(x, 8),
                ExtractUint(x, 12)
                );
            Array.Clear(x, 0, x.Length);

            using (n)
            {

                // d = modulus * 2**32
                var d = new Ff3DivisionAccumulator(modulus.ShiftedDivisor.High, modulus.ShiftedDivisor.Mid, modulus.ShiftedDivisor.Low, 0u);

                // okay, we need to compute the integer value of 'x' modulo 'modulus'
                for (var i = 0; i <= 32 + modulus.ShiftCount; i++)
                {
                    //Debug.Print("({0,2}) n = {1}, d = {2}", i, n, d);
                    if (n >= d)
                        n.Sub(d);
                    d.Shr();
                }

                //Debug.Print("Final: {0} ({0:D})", n.To96Bit());

                return n.To96Bit();
            }
        }

        static Ff3Accumulator Num(uint radix, ArraySegment<ushort> X)
        {
            var A = X.Array;
            var acc = Ff3Accumulator.Zero;
            for (var i = 0; i < X.Count; i++)
            {
                acc = acc.MultiplyAdd(radix, A[X.Offset + i]);
            }
            return acc;
        }

        static Ff3Accumulator NumRev(uint radix, ArraySegment<ushort> X)
        {
            var A = X.Array;
            var acc = Ff3Accumulator.Zero;
            for (var i = X.Count - 1; i >= 0; i--)
            {
                acc = acc.MultiplyAdd(radix, A[X.Offset + i]);
            }
            return acc;
        }


        static void Rev<T>(T[] dest, T[] src)
        {
            for (int i = 0; i < src.Length; i++)
            {
                dest[dest.Length - i] = src[i];
            }
        }

        internal static void Reverse<T>(T[] x)
        {
            for (int i = 0; i < x.Length / 2; i++)
            {
                var t = x[i];
                x[i] = x[x.Length - i - 1];
                x[x.Length - i - 1] = t;
            }
        }

        static void StrRev(ArraySegment<ushort> x, uint radix, Ff3Accumulator n)
        {
            var radix_divisor = new Ff3Accumulator(radix);
            int i = 0;
            while (!n.IsZero)
            {
                var (q, r) = n.DivRem(radix_divisor);
                n = q;
                x.Array[x.Offset + i] = (ushort)r.Low;
                i++;
            }
            while (i < x.Count) { x.Array[x.Offset + i] = 0; i++; }
        }

        [Conditional("TRACEMODE")]
        static void Trace(string message)
        {
            Debug.Print(message);
        }
        [Conditional("TRACEMODE")]
        static void Trace(string format, params object[] args)
        {
            Debug.Print(format, args);
        }

        static string DebugT(byte[] t)
        {
            StringBuilder sb = new StringBuilder();
            for (var i = 0; i < t.Length; i++)
            {
                if (i > 0 && ((i & 3) == 0)) sb.Append(' ');
                var b = t[i];
                sb.Append(b.ToString("x2"));
            }
            //foreach (var b in t) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        static string DebugP(byte[] p)
        {
            return string.Join(", ", p);
        }

        static string DebugStr(ArraySegment<ushort> s)
        {
            return string.Join(" ", s);
        }

        /// <summary>
        /// Encrypts a message.
        /// </summary>
        /// <param name="tweak">Optional "tweak" value</param>
        /// <param name="input">The plaintext to be enciphered (<strong>THE CONTENTS OF THIS BUFFER ARE DESTROYED)</strong></param>
        /// <remarks></remarks>
        /// <returns>The resulting ciphertext.</returns>
        /// <exception cref="ArgumentException">The length of <paramref name="tweak"/> is not valid.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> is too short or too long.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> contains values greater than or equal to the radix supplied in the constructor.
        /// </exception>
        public ushort[] Encrypt(byte[] tweak, ushort[] input)
        {
            ushort[] result = new ushort[input.Length];
            Encrypt(tweak, input, result);
            return result;
        }

        /// <summary>
        /// Encrypts a value.
        /// </summary>
        /// <param name="tweak">Optional "tweak" value</param>
        /// <param name="input">The plaintext to be enciphered (<strong>THE CONTENTS OF THIS BUFFER ARE DESTROYED)</strong></param>
        /// <param name="output">The output buffer that receives the ciphertext.  (This may be the same buffer as <paramref name="input"/>.)</param>
        /// <remarks></remarks>
        /// <returns>The resulting ciphertext.</returns>
        /// <exception cref="ArgumentException">The length of <paramref name="tweak"/> is not valid.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> is too short or too long.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> contains values greater than or equal to the radix supplied in the constructor.
        /// <exception cref="ArgumentNullException"><paramref name="output"/> is too short to hold the output.</exception>
        /// </exception>
        public void Encrypt(byte[] tweak, ushort[] input, ushort[] output)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output.Length < input.Length) throw new ArgumentException("Output buffer is too small to hold ciphertext", nameof(output));

            var T = tweak;
            var X = input;
            var result = output;
            if (X.Length < minlen || X.Length > maxlen) throw new ArgumentException("Value length out of range", nameof(input));
            if (T != null && T.Length != FF3_1_MAX_TWEAK_SIZE && (EnableFF3TweakSupport == false || T.Length != FF3_LEGACY_TWEAK_SIZE))
                throw new ArgumentException("Tweak length is not valid", nameof(tweak));

            // we need to use the underlying cipher algorithm directly
            ciph.Mode = CipherMode.ECB;
            ciph.Padding = PaddingMode.None;

            for (int i = 0; i < X.Length; i++)
                if (X[i] >= radix) throw new ArgumentException("Value contains invalid symbols", nameof(input));
            using (var ciphTransform = ciph.CreateEncryptor())
            {
                var P = new byte[/*4 + 12*/ ciph.BlockSize / 8];
                var S = new byte[P.Length];
                try
                {
                    var n = X.Length;
                    // 1. Let u = ceil(n/2); v = n - u.
                    var u = (n + 1) / 2;
                    var v = n - u;

                    Trace($"u = <{u}>, v = <{v}>");

                    var u_modulus = new Ff3Divisor(Ff3Accumulator.CreateExponent(radix, (uint)u));
                    var v_modulus = (u == v) ? u_modulus : new Ff3Divisor(Ff3Accumulator.CreateExponent(radix, (uint)v));

                    // 2. Let A = X[1..u]; B = X[u+1..n]
                    var A = new ArraySegment<ushort>(X, 0, u);
                    var B = new ArraySegment<ushort>(X, u, X.Length - u);

                    Trace("A = {0}", string.Join(" ", A));
                    Trace("B = {0}", string.Join(" ", B));

                    // 3. Let T[L] = T[0..27] || '0000' and T[R] = T[32..55] || T[28..31] || '0000'
                    var TL = CreateTL(T);
                    var TR = CreateTR(T);

                    Trace($"T_L = {DebugT(TL)}, T_R = {DebugT(TR)}");

                    // 4. For i from 0 to 7:
                    for (var i = 0; i < FF3_1_NUM_ROUNDS; i++)
                    {
                        Trace($"Round #{i}");

                        // i. If i is even, let m=u and W=T[R], else lset m=v and W=T[L].
                        var (m, W, m_modulus) = ((i & 1) == 0) ? (u, TR, u_modulus) : (v, TL, v_modulus);

                        Trace($"m = <{m}>, W = {DebugT(W)}");

                        // ii. Let P = W xor [i-as-4-bytes] || [NUM_radix(REV(B))]
                        P[0] = (byte)(W[0] ^ ((i >> 24) & 0xFF));
                        P[1] = (byte)(W[1] ^ ((i >> 16) & 0xFF));
                        P[2] = (byte)(W[2] ^ ((i >> 8) & 0xFF));
                        P[3] = (byte)(W[3] ^ ((i) & 0xFF));
                        var p_trailer = NumRev(radix, B);
                        p_trailer.CopyTo(P, 4);
                        Trace($"P = [ {DebugP(P)} ]");

                        // iii. Let S = REVB(CIPH_REVB(K) REVB(P))
                        Reverse(P);
                        ciphTransform.TransformBlock(P, 0, P.Length, S, 0);
                        Reverse(S);

                        Trace($"S = {DebugT(S)}");
                        // iv. Let y = NUM(S)
                        // Note that the only place we're using 'y' is in a modulus operation, we pre-compute y modulo
                        var y = Num(S, m_modulus);
                        Trace($"y = {y:D} (modulus = {m_modulus})");
                        // v. Let c = (NUM_radix(REV(A)) + y) mod radix**m
                        var c = (NumRev(radix, A) + y) % m_modulus;
                        Trace($"c = {c:D}");
                        // vi. Let C = REV(STR_m_radix(c))
                        var C = A;
                        if (C.Count != m) throw new Exception("Internal logic error detected (sanity check failed)");
                        StrRev(C, radix, c);
                        Trace($"C = {DebugStr(C)}");
                        // vii. Let A = B.
                        A = B;
                        Trace($"A = {DebugStr(A)}");
                        // viii. Let B = C.
                        B = C;
                    }
                    // 5. Return A || B
                    if (X == result)
                    {
                        // either A.Offset < B.Offset or A.Offset > B.Offset
                        // if A.Offset < B.Offset, then X is already sorted the way we want
                        // otherwise, we need to swap A and B
                        if (A.Offset > B.Offset)
                        {
                            // NOTE: I don't think this can actually happen with an even number of rounds?
                            // okay, we need to swap A and B
                            // Note, then, that A.Count <= B.Count
                            // this is because A and B are actually reversed from how they were initialized all the way at the top
                            var temp = new ushort[B.Count];
                            Array.Copy(B.Array, B.Offset, temp, 0, B.Count);
                            Array.Copy(A.Array, A.Offset, result, 0, A.Count);
                            temp.CopyTo(result, A.Count);
                        }
                    }
                    else
                    {
                        Array.Copy(A.Array, A.Offset, result, 0, A.Count);
                        Array.Copy(B.Array, B.Offset, result, A.Count, B.Count);
                    }
                    return;
                }
                finally
                {
                    Array.Clear(P, 0, P.Length);
                    Array.Clear(S, 0, S.Length);
                    if (X != result) Array.Clear(X, 0, X.Length);
                }
            }
        }

        /// <summary>
        /// If true, 64-bit (8-byte) tweaks are permitted. If false, only 56-bit (7-byte) tweaks are permitted.
        /// </summary>
        /// <remarks>
        /// The original FF3 algorithm specified an 8-byte tweaks,
        /// but that was proven insecure when multiple values are enciphered with the same key using different tweaks.
        /// FF3-1 only allows 7-byte tweaks.
        /// </remarks>
        public bool EnableFF3TweakSupport { get; set; }

        /// <summary>
        /// Decrypts a message.
        /// </summary>
        /// <param name="tweak">Optional "tweak" value</param>
        /// <param name="input">The value to be deciphered (<strong>THE CONTENTS OF THIS BUFFER ARE DESTROYED)</strong></param>
        /// <remarks></remarks>
        /// <returns>The resulting plaintext.</returns>
        /// <exception cref="ArgumentException">The length of <paramref name="tweak"/> is not valid.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> is too short or too long.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> contains values greater than or equal to the radix supplied in the constructor.
        /// </exception>
        public ushort[] Decrypt(byte[] tweak, ushort[] input)
        {
            ushort[] result = new ushort[input.Length];
            Decrypt(tweak, input, result);
            return result;
        }

        /// <summary>
        /// Decrypts a value.
        /// </summary>
        /// <param name="tweak">Optional "tweak" value</param>
        /// <param name="input">The value to be deciphered (<strong>THE CONTENTS OF THIS BUFFER ARE DESTROYED)</strong></param>
        /// <param name="output">The output buffer that receives the plaintext.  (This may be the same buffer as <paramref name="input"/>.)</param>
        /// <remarks></remarks>
        /// <returns>The resulting ciphertext.</returns>
        /// <exception cref="ArgumentException">The length of <paramref name="tweak"/> is not valid.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> is too short or too long.</exception>
        /// <exception cref="ArgumentException"><paramref name="input"/> contains values greater than or equal to the radix supplied in the constructor.
        /// <exception cref="ArgumentNullException"><paramref name="output"/> is too short to hold the output.</exception>
        /// </exception>
        public void Decrypt(byte[] tweak, ushort[] input, ushort[] output)
        {
            if (output == null) throw new ArgumentNullException(nameof(output));
            if (input == null) throw new ArgumentNullException(nameof(input));
            if (output.Length < input.Length) throw new ArgumentException("Output buffer is too small to hold ciphertext", nameof(output));

            var T = tweak;
            var X = input;
            var result = output;
            if (X.Length < minlen || X.Length > maxlen) throw new ArgumentException("Value length out of range", nameof(input));

            if (T != null && T.Length != FF3_1_MAX_TWEAK_SIZE && (EnableFF3TweakSupport == false || T.Length != FF3_LEGACY_TWEAK_SIZE))
                throw new ArgumentException("Tweak length is not valid", nameof(tweak));

            // we need to use the underlying cipher algorithm directly
            ciph.Mode = CipherMode.ECB;
            ciph.Padding = PaddingMode.None;

            for (int i = 0; i < X.Length; i++)
                if (X[i] >= radix) throw new ArgumentException("Value contains invalid symbols", nameof(input));
            using (var ciphTransform = ciph.CreateEncryptor())
            {
                var P = new byte[4 + 12];
                var S = new byte[P.Length];
                try
                {
                    var n = X.Length;
                    // 1. Let u = ceil(n/2); v = n - u.
                    var u = (n + 1) / 2;
                    var v = n - u;

                    Trace($"u = <{u}>, v = <{v}>");

                    var u_modulus = new Ff3Divisor(Ff3Accumulator.CreateExponent(radix, (uint)u));
                    var v_modulus = (u == v) ? u_modulus : new Ff3Divisor(Ff3Accumulator.CreateExponent(radix, (uint)v));

                    // 2. Let A = X[1..u]; B = X[u+1..n]
                    var A = new ArraySegment<ushort>(X, 0, u);
                    var B = new ArraySegment<ushort>(X, u, X.Length - u);

                    Trace("A = {0}", string.Join(" ", A));
                    Trace("B = {0}", string.Join(" ", B));

                    // 3. Let T[L] = T[0..27] || '0000' and T[R] = T[32..55] || T[28..31] || '0000'
                    var TL = CreateTL(T);
                    var TR = CreateTR(T);

                    Trace($"T_L = {DebugT(TL)}, T_R = {DebugT(TR)}");

                    // 4. For i from 7 to 0:				
                    for (var i = FF3_1_NUM_ROUNDS - 1; i >= 0; i--)
                    {
                        Trace($"Round #{i}");

                        // i. If i is even, let m=u and W=T[R], else lset m=v and W=T[L].
                        var (m, W, m_modulus) = ((i & 1) == 0) ? (u, TR, u_modulus) : (v, TL, v_modulus);

                        Trace($"m = <{m}>, W = {DebugT(W)}");

                        // ii. Let P = W xor [i-as-4-bytes] || [NUM_radix(REV(A))]
                        P[0] = (byte)(W[0] ^ ((i >> 24) & 0xFF));
                        P[1] = (byte)(W[1] ^ ((i >> 16) & 0xFF));
                        P[2] = (byte)(W[2] ^ ((i >> 8) & 0xFF));
                        P[3] = (byte)(W[3] ^ ((i) & 0xFF));
                        var p_trailer = NumRev(radix, A);
                        p_trailer.CopyTo(P, 4);

                        Trace($"P = [ {DebugP(P)} ]");
                        // iii. Let S = REVB(CIPH_REVB(K) REVB(P))
                        Reverse(P);
                        ciphTransform.TransformBlock(P, 0, P.Length, S, 0);
                        Reverse(S);

                        Trace($"S = {DebugT(S)}");

                        // iv. Let y = NUM(S)
                        // Note that the only place we're using 'y' is in a modulus operation, we pre-compute y modulo
                        var y = Num(S, m_modulus);
                        // v. Let c = (NUM_radix(REV(A)) + y) mod radix**m
                        // Note that, due to limitations of the Ff3Accumulator implementation (specifically: no support for negative values), we need to add m_modulus to avoid problems
                        var c = (NumRev(radix, B) + m_modulus.Value - y) % m_modulus;

                        Trace($"c = {c:D}");
                        // vi. Let C = REV(STR_m_radix(c))
                        var C = B;
                        if (C.Count != m) throw new Exception("Internal logic error detected (sanity check failed)");
                        StrRev(C, radix, c);
                        Trace($"C = {DebugStr(C)}");
                        // vii. Let B = A.
                        B = A;
                        Trace($"B = {DebugStr(B)}");
                        // viii. Let A = C.
                        A = C;
                    }
                    // 5. Return A || B
                    if (X == result)
                    {
                        // either A.Offset < B.Offset or A.Offset > B.Offset
                        // if A.Offset < B.Offset, then X is already sorted the way we want
                        // otherwise, we need to swap A and B
                        if (A.Offset > B.Offset)
                        {
                            // NOTE: I don't think this can actually happen with an even number of rounds?
                            // okay, we need to swap A and B
                            // Note, then, that A.Count <= B.Count
                            // this is because A and B are actually reversed from how they were initialized all the way at the top
                            var temp = new ushort[B.Count];
                            Array.Copy(B.Array, B.Offset, temp, 0, B.Count);
                            Array.Copy(A.Array, A.Offset, result, 0, A.Count);
                            temp.CopyTo(result, A.Count);
                        }
                    }
                    else
                    {
                        Array.Copy(A.Array, A.Offset, result, 0, A.Count);
                        Array.Copy(B.Array, B.Offset, result, A.Count, B.Count);
                    }
                    return;
                }
                finally
                {
                    Array.Clear(P, 0, P.Length);
                    Array.Clear(S, 0, S.Length);
                    if (X != result) Array.Clear(X, 0, X.Length);
                }
            }
        }

    }
}
