using System;
using System.Collections.Generic;
using System.Text;

namespace Indulj.Ff3
{
    static class Ff3Helpers
    {
        // interesting limitation: you cannot use a Span in a ValueTuple (probably because there's no way to prevent the
        // ValueTuple from being boxed)

        public static (ushort[] raw_value, (int offset, char value)[] formattingChars) DecodeString(string value, string charset)
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
            var original_length = raw_value.Length + formattingChars.Length;
            var sb = new StringBuilder(original_length);
            int next_fc_offset = (formattingChars.Length > 0 ? formattingChars[0].offset : original_length);

            for (int i = 0, j = 0; i < original_length;)
            {
                while (i == next_fc_offset)
                {
                    i++;
                    sb.Append(formattingChars[0].ch);
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
                    sb.Append(charset[raw_value[j++]]);
                }
            }

            return sb.ToString();
        }

    }
}
