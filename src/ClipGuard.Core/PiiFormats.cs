using System.Text;

namespace ClipGuard.Core;

/// <summary>
/// 規則檔（#27 的個資包）用到、但 regex 寫不出來的部分：信用卡的分組（<c>finder: card-groups</c>）、
/// 各格式的驗證（<c>validate</c>）和遮罩前的標準寫法（<c>mask.canonical</c>）。
/// 每一個名稱在 extension/lib/pii.js 都有同樣的實作。輸入都是 <see cref="SecretRules.AsciiView"/> 或正規化後的文字。
/// </summary>
internal static class PiiFormats
{
    // ---------- validate ----------

    public static Func<string, bool>? Validator(string name) => name switch
    {
        "jwt-header" => SecretValidators.IsJwt,
        "tw-id" => IsTaiwanId,
        "tw-ubn" => s => Checksums.IsValidBusinessId(s),
        "iban" => s => Checksums.IsValidIban(AlnumUpper(s)),
        "e164" => s => Checksums.IsPlausibleE164(Digits(s)),
        "cn-id" => s => Checksums.IsValidChinaResidentId(AlnumUpper(s)),
        "jp-my-number" => s => Checksums.IsValidMyNumber(Digits(s)),
        "hk-id" => s => Checksums.IsValidHongKongId(AlnumUpper(s)),
        "sg-nric" => s => Checksums.IsValidSingaporeNric(AlnumUpper(s)),
        "us-ssn" => IsUsSsn,
        _ => null,
    };

    // 身分證、居留證：分隔符號最多 3 個（A 123 456 789），\r\n 算一個（#22）。
    private const int MaxIdSeparators = 3;

    private static bool IsTaiwanId(string s)
    {
        var id = AlnumUpper(s);
        var separators = s.Length - id.Length - s.Count(c => c == '\r');
        return separators <= MaxIdSeparators && Checksums.IsValidTaiwanId(id);
    }

    // SSN 的兩個分隔符號要一樣（123-45-6789、123 45 6789），或都沒有。
    private static bool IsUsSsn(string s)
    {
        var digits = Digits(s);
        if (digits.Length != 9) return false;
        if (s.Length == 11 && s[3] != s[6]) return false;
        return s.Length is 9 or 11 && Checksums.IsPlausibleUsSsn(digits);
    }

    // ---------- mask.canonical ----------

    public static Func<string, string>? Canonical(string name) => name switch
    {
        "alnum-upper" => AlnumUpper,
        "digits" => Digits,
        "tw-mobile" => TaiwanMobile,
        "e164" => s => "+" + Digits(s),
        _ => null,
    };

    public static string Digits(string s) => new(s.Where(char.IsAsciiDigit).ToArray());

    public static string AlnumUpper(string s) => new(s.Where(char.IsAsciiLetterOrDigit).Select(char.ToUpperInvariant).ToArray());

    // +886 912…、886 0912… 都寫成 0912…，遮罩跟國內寫法一樣。
    private static string TaiwanMobile(string s)
    {
        var digits = Digits(s);
        return digits.StartsWith("886", StringComparison.Ordinal) ? "0" + digits[(digits[3] == '0' ? 4 : 3)..] : digits;
    }

    // ---------- finder ----------

    public static Func<string, IEnumerable<(int Index, int Length)>>? Finder(string name) => name switch
    {
        "card-groups" => CardCandidates,
        _ => null,
    };

    private readonly record struct Group(int Start, int End, char SepBefore);

    /// <summary>
    /// 先切出「數字組」：用單一分隔符號（空白、點、連字號、換行）接起來的一串數字，
    /// 再從裡面找連續幾組合起來是 13–19 碼、分組方式像卡號、開頭與 Luhn 都對的。
    /// 分組方式限定 4-4-4-4（最後一組 1–4 碼）、Amex 4-6-5、Diners 4-6-4，而且分隔符號要一致
    /// （換行可以取代任何一種，例如卡號在第二組後面折行）。這樣日期清單（2024-01-15 2024-02-16）、
    /// IP、版本號碼這類「數字＋分隔符號」的組合不會被硬湊成卡號。
    /// regex 做不到「多組裡挑第一個 Luhn 對的」，所以這是程式寫的 finder，不是規則檔的 regex。
    /// </summary>
    public static IEnumerable<(int Index, int Length)> CardCandidates(string text)
    {
        var groups = new List<Group>();
        var i = 0;
        while (i < text.Length)
        {
            if (!char.IsAsciiDigit(text[i])) { i++; continue; }

            // 收集一整串數字組。
            groups.Clear();
            var sep = '\0';
            while (true)
            {
                var start = i;
                while (i < text.Length && char.IsAsciiDigit(text[i])) i++;
                groups.Add(new(start, i, sep));
                var next = SeparatorAt(text, i, out var kind);
                if (next < 0) break;
                sep = kind;
                i = next;
            }

            for (var g = 0; g < groups.Count; g++)
            {
                var total = 0;
                for (var h = g; h < groups.Count; h++)
                {
                    total += groups[h].End - groups[h].Start;
                    if (total > 19) break;
                    // 多組時，最後一組以外都要是 4 碼（Amex／Diners 的第二組是 6 碼）；不符合就不用再往後湊。
                    // 否則「1 1 1 1…」這種內容每一組都要往後試十幾組，O(n × 19²)。
                    if (h > g)
                    {
                        var prev = groups[h - 1].End - groups[h - 1].Start;
                        if (prev != 4 && !(h - 1 == g + 1 && prev == 6)) break;
                    }
                    if (total < 13 || !IsCardGrouping(groups, g, h)) continue;

                    var digits = DigitsOf(text, groups, g, h);
                    if (!IsCardPrefix(digits) || !Checksums.IsValidLuhn(digits)) continue;
                    yield return (groups[g].Start, groups[h].End - groups[g].Start);
                    g = h;   // 下一個候選從這張卡後面開始，不重疊
                    break;
                }
            }
        }
    }

    /// <summary>position 處若是「分隔符號後面接數字」，回傳那個數字的位置，否則 -1。</summary>
    private static int SeparatorAt(string text, int position, out char kind)
    {
        kind = '\0';
        if (position >= text.Length) return -1;
        var c = text[position];
        int next;
        if (c is ' ' or '.' or '-') { kind = c; next = position + 1; }
        else if (c == '\n') { kind = '\n'; next = position + 1; }
        else if (c == '\r' && position + 1 < text.Length && text[position + 1] == '\n') { kind = '\n'; next = position + 2; }
        else return -1;
        return next < text.Length && char.IsAsciiDigit(text[next]) ? next : -1;
    }

    private static bool IsCardGrouping(List<Group> groups, int first, int last)
    {
        if (first == last) return true;

        var sep = '\0';
        for (var k = first + 1; k <= last; k++)
        {
            var s = groups[k].SepBefore;
            if (s == '\n') continue;
            if (sep == '\0') sep = s;
            else if (sep != s) return false;
        }

        int Len(int k) => groups[k].End - groups[k].Start;
        var count = last - first + 1;
        if (count == 3 && Len(first) == 4 && Len(first + 1) == 6 && Len(last) is 4 or 5) return true;   // Diners、Amex
        for (var k = first; k < last; k++)
            if (Len(k) != 4) return false;
        return Len(last) is >= 1 and <= 4;
    }

    private static string DigitsOf(string text, List<Group> groups, int first, int last)
    {
        var sb = new StringBuilder(19);
        for (var k = first; k <= last; k++) sb.Append(text, groups[k].Start, groups[k].End - groups[k].Start);
        return sb.ToString();
    }

    /// <summary>主要發卡組織的號碼開頭與長度（ISO/IEC 7812 IIN 範圍）。</summary>
    private static bool IsCardPrefix(string d)
    {
        int P(int n) => int.Parse(d.AsSpan(0, n));
        var len = d.Length;
        return d[0] switch
        {
            '4' => len is 13 or 16 or 19,                                               // Visa
            '5' => P(2) is >= 51 and <= 55 && len == 16,                                // Mastercard
            '2' => P(4) is >= 2221 and <= 2720 && len == 16,                            // Mastercard 2-series
            '3' => (P(2) is 34 or 37 && len == 15)                                      // Amex
                   || (P(4) is >= 3528 and <= 3589 && len is >= 16 and <= 19)           // JCB
                   || ((P(2) is 36 or 38 || P(3) is >= 300 and <= 305) && len is >= 14 and <= 19), // Diners
            '6' => (d.StartsWith("6011", StringComparison.Ordinal) || d.StartsWith("65", StringComparison.Ordinal)
                    || P(3) is >= 644 and <= 649 || d.StartsWith("62", StringComparison.Ordinal)) && len is >= 16 and <= 19, // Discover / UnionPay
            _ => false,
        };
    }
}
