using System.Text;

namespace ClipGuard.Core;

/// <summary>
/// 機密偵測用的正規化結果：比對用的文字，加上每個字對回原文的位置。
/// 遮罩（貼遮罩版）要換掉的是原文的範圍，所以結果的位置一律要換回原文。
/// </summary>
internal sealed class NormalizedText
{
    private readonly int[] _start;
    private readonly int[] _end;

    public string Text { get; }

    public NormalizedText(string text, int[] start, int[] end)
    {
        Text = text;
        _start = start;
        _end = end;
    }

    /// <summary>正規化文字中的 [index, index+length) 對應到原文的範圍（含中間被刪掉的零寬字元）。</summary>
    public (int Index, int Length) ToOriginal(int index, int length)
    {
        var start = _start[index];
        return (start, _end[index + length - 1] - start);
    }
}

/// <summary>
/// 機密比對前的正規化（#22）。只給機密偵測用，跟指令偵測的 <see cref="CommandNormalizer"/> 無關。
/// <list type="bullet">
/// <item>逐字做 NFKC：全形英數字、全形標點、全形空白變半形（<c>Ａ１２３</c> → <c>A123</c>）。</item>
/// <item>dash 變體（U+2010–2015、U+2212、U+FE58）換成 <c>-</c>。</item>
/// <item>刪掉零寬字元（U+200B–200D、U+2060、U+FEFF）和軟連字號 U+00AD，號碼中間夾了這些字也比得到。</item>
/// </list>
/// 逐字而不是整段做 NFKC，才能記住每個字來自原文哪裡。
/// </summary>
internal static class SecretTextNormalizer
{
    // BMP 字元的 NFKC 結果快取。字串不可變，多執行緒同時填同一格也沒關係。
    private static readonly string?[] Cache = new string?[char.MaxValue + 1];

    public static NormalizedText Normalize(string text, int from, int to)
    {
        var sb = new StringBuilder(to - from);
        var start = new List<int>(to - from);
        var end = new List<int>(to - from);

        for (var i = from; i < to; i++)
        {
            var c = text[i];

            // 常見字元直接照抄：ASCII、CJK 統一表意文字、韓文音節的 NFKC 結果都是自己。
            if (c < 0x80 || c is >= '㐀' and <= '鿿' || c is >= '가' and <= '힣')
            {
                Append(c, i, i + 1);
                continue;
            }

            if (c is '​' or '‌' or '‍' or '⁠' or '﻿' or '­')
                continue;

            if (c is >= '‐' and <= '―' or '−' or '﹘')
            {
                Append('-', i, i + 1);
                continue;
            }

            string mapped;
            var width = 1;
            if (char.IsHighSurrogate(c) && i + 1 < to && char.IsLowSurrogate(text[i + 1]))
            {
                mapped = text.Substring(i, 2).Normalize(NormalizationForm.FormKC);
                width = 2;
            }
            else if (char.IsSurrogate(c))
            {
                mapped = c.ToString();   // 落單的 surrogate 不能 Normalize，照抄
            }
            else
            {
                mapped = Cache[c] ??= c.ToString().Normalize(NormalizationForm.FormKC);
            }

            foreach (var m in mapped) Append(m, i, i + width);
            i += width - 1;
        }

        return new NormalizedText(sb.ToString(), [.. start], [.. end]);

        void Append(char c, int s, int e)
        {
            sb.Append(c);
            start.Add(s);
            end.Add(e);
        }
    }
}
