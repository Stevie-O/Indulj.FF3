using System;
using System.Collections.Generic;
using System.Text;

namespace Indulj.Ff3
{
    static class Ff3Helpers
    {
        // interesting limitation: you cannot use a Span in a ValueTuple (probably because there's no way to prevent the
        // ValueTuple from being boxed)

        public static (ushort[] raw_value, (int offset, char value)[] formattingChars) DecodeString(ReadOnlySpan<char> value, string charset)
        {
            var formattingChars = new List<(int offset, char value)>();
            var raw_value = new List<ushort>(value.Length);
            int ctext_len = 0;
            for (int i = 0; i < value.Length; i++)
            {
                char ch = value[i];
                int s_value = charset.IndexOf(ch);
                if (s_value < 0 || s_value > ushort.MaxValue)
                {
                    // not an encrypted character
                    formattingChars.Add((i, ch));
                }
                else
                {
                    raw_value.Add((ushort)s_value);
                    ctext_len++;
                }
            }
            return (raw_value.ToArray(), formattingChars.ToArray());
        }

        public static string EncodeString(ushort[] raw_value, string charset, Span<(int offset, char ch)> formattingChars)
        {
            var len = raw_value.Length + formattingChars.Length;
            //Span<char> buffer = stackalloc char[len];
            var buffer = new char[len];
            EncodeString(raw_value, charset, formattingChars, buffer);
            return new string(buffer);
        }

        public static int EncodeString(ushort[] raw_value, string charset, Span<(int offset, char ch)> formattingChars, Span<char> dest)
        {
            var original_length = raw_value.Length + formattingChars.Length;
            int output_offset = 0;
            int next_fc_offset = (formattingChars.Length > 0 ? formattingChars[0].offset : original_length);

            for (int i = 0, j = 0; i < original_length;)
            {
                while (i == next_fc_offset)
                {
                    i++;
                    dest[output_offset++] = formattingChars[0].ch;
                    formattingChars = formattingChars.Slice(1);
                    if (formattingChars.Length > 0)
                    {
                        next_fc_offset = formattingChars[0].offset;
                    }
                    else
                    {
                        next_fc_offset = original_length;
                        break;
                    }
                }

                for (; i < next_fc_offset; i++)
                {
                    dest[output_offset++] = charset[raw_value[j++]];
                }
            }

            return output_offset;
        }

    }
}
