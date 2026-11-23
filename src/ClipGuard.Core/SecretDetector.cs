using System.Text;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

public enum SecretKind
{
    NationalId,
    ResidentCertificate,
    BusinessId,
    CreditCard,
    MobilePhone,
    ApiKey,
    /// <summary>使用者自行登記的機密（見 <see cref="RegisteredSecretStore"/>）。</summary>
    Registered,
}

/// <summary>
/// 一筆偵測結果。刻意不保留原文，只留遮罩後的字串與位置，避免結果物件被誤拿去顯示或記錄。
/// <see cref="Index"/>／<see cref="Length"/> 一律是原文（正規化之前）的位置。
/// </summary>
public sealed record SecretMatch(SecretKind Kind, string Label, string Masked, int Index, int Length);

/// <summary>
/// 在任意文字裡找出常見機密格式。流程：正規化（全形轉半形、去零寬字元）→ regex 切出候選字串
/// → 驗檢查碼或前綴 → 遮罩 → 位置換回原文。不需要使用者事先登記。
/// </summary>
public static class SecretDetector
{
    /// <summary>
    /// 最多分析多少字。超過時分析開頭和結尾各一半（機密常在文件頭尾，例如 .env、log 最後幾行），
    /// 中間不分析，避免在 UI 執行緒上卡住（1 Mi 字的最壞情況約 0.15 秒）。
    /// 等於系統匣程式讀剪貼簿的上限（#24 的 ClipboardLimits.MaxAnalyzedChars），超過的部分本來就讀不到。
    /// </summary>
    public const int MaxScanLength = 1 << 20;

    // 分段分析：每段前進 SegmentStep 字，往後多看 Overlap 字、往前多看 Context 字。
    // 長度 < Overlap 的機密一定完整落在「起點所屬的那一段」裡，所以不會因為切段而漏掉或切斷。
    internal const int SegmentStep = 64 * 1024;
    internal const int Overlap = 8 * 1024;
    // 往前看的字數：前後邊界的 lookbehind、統編前面的關鍵字（關鍵字 + 20 字）。
    private const int Context = 64;

    private const RegexOptions Opts = RegexOptions.CultureInvariant;

    // 號碼中間允許的分隔：單一的空白、點、連字號，或一個換行（#22）。零寬字元在正規化時已經刪掉。
    private const string Sep = @"(?:[ .\-]|\r?\n)";

    // 身分證／居留證：前後不能緊鄰英數字，避免從更長的識別碼中間切出來。
    // 分隔符號最多 3 個（A 123 456 789），驗證時再數。
    private static readonly Regex TaiwanId = new(
        $@"(?<![A-Za-z0-9])[A-Za-z]{Sep}?[1289A-Da-d](?:{Sep}?[0-9]){{8}}(?![A-Za-z0-9])", Opts);
    private const int MaxIdSeparators = 3;

    // 統編只有 8 碼數字，且「可被 5 整除」讓約 1/5 的隨機 8 位數都會通過，
    // 單獨出現時跟日期（20231122）、訂單號碼分不出來，所以要求前面 20 字內有關鍵字。
    private static readonly Regex BusinessId = new(
        @"(?:統一編號|統編|營利事業|稅籍|VAT|Tax\s{0,3}ID)[^0-9\r\n]{0,20}(?<![0-9])([0-9]{8})(?![0-9])",
        Opts | RegexOptions.IgnoreCase);

    // 手機：09 加 8 碼（0912-345-678、0912 345678），+886／886 開頭（可以多寫一個 0），
    // 或是把 09 寫成區碼的 (09)55666777。
    private static readonly Regex Mobile = new(
        $@"(?<![0-9+])(?:(?:\+?886{Sep}?0?|0)9[0-9]{{2}}{Sep}?[0-9]{{3}}{Sep}?[0-9]{{3}}"
        + $@"|\(09\){Sep}?(?:[0-9]{{4}}{Sep}?[0-9]{{4}}|[0-9]{{2}}{Sep}?[0-9]{{3}}{Sep}?[0-9]{{3}}))(?![0-9])", Opts);

    // API key、JWT、PEM 和上下文＋亂度的規則都在共用規則檔裡（rules/*.json，見 SecretRules，#26）。
    // 個資（有檢查碼或要特殊分組的）還留在程式裡，#27 再拆。

    // 優先順序：前面的類型先佔位置，後面重疊的候選會被丟掉。規則檔的規則依檔案 priority 排在個資前面。
    private static readonly IReadOnlyList<SecretRule> Rules = SecretRules.All;
    private const int RankRule = 0;                      // 0 .. Rules.Count-1
    private static readonly int RankId = RankRule + Rules.Count;
    private static readonly int RankCard = RankId + 1;
    private static readonly int RankBusinessId = RankId + 2;
    private static readonly int RankMobile = RankId + 3;
    private static readonly int RankCount = RankId + 4;

    public static IReadOnlyList<SecretMatch> Find(string? text)
    {
        if (string.IsNullOrEmpty(text)) return [];

        // 每種類型各一份清單：同一種類型的結果依位置排序、互不重疊。
        var byRank = new List<SecretMatch>[RankCount];
        for (var r = 0; r < RankCount; r++) byRank[r] = [];

        foreach (var (from, to) in ScanRanges(text.Length))
        {
            for (var s = from; s < to; s += SegmentStep)
            {
                var ownedEnd = Math.Min(s + SegmentStep, to);
                var segStart = Math.Max(0, s - Context);
                var segEnd = Math.Min(text.Length, ownedEnd + Overlap);
                var norm = SecretTextNormalizer.Normalize(text, segStart, segEnd);

                FindInSegment(norm, (rank, match) =>
                {
                    // 只收起點在這段負責範圍內的結果；碰到段尾的可能被切斷，交給下一段（不會發生在 < Overlap 的機密上）。
                    if (match.Index < s || match.Index >= ownedEnd) return;
                    if (segEnd < text.Length && match.Index + match.Length >= segEnd) return;
                    byRank[rank].Add(match);
                });
            }
        }

        var kept = new List<SecretMatch>();
        foreach (var list in byRank) kept = Merge(kept, list);
        return kept;
    }

    /// <summary>要分析的範圍：整段，或太長時的開頭與結尾。</summary>
    private static IEnumerable<(int From, int To)> ScanRanges(int length)
    {
        if (length <= MaxScanLength)
        {
            yield return (0, length);
            yield break;
        }
        yield return (0, MaxScanLength / 2);
        yield return (length - MaxScanLength / 2, length);
    }

    private static void FindInSegment(NormalizedText norm, Action<int, SecretMatch> add)
    {
        var text = norm.Text;

        SecretMatch Make(SecretKind kind, string label, string masked, int index, int length)
        {
            var (i, l) = norm.ToOriginal(index, length);
            return new(kind, label, masked, i, l);
        }

        // 規則檔：在 ASCII 版本上比對（位置不變），先用 keywords 篩掉不可能命中的規則。
        var ascii = SecretRules.AsciiView(text);
        var lower = ascii.ToLowerInvariant();
        for (var k = 0; k < Rules.Count; k++)
        {
            var rule = Rules[k];
            if (!rule.KeywordsPresent(lower)) continue;
            foreach (var (index, length, secret) in rule.Scan(ascii, text))
                add(RankRule + k, Make(rule.Kind, rule.Label,
                    rule.PemBlock ? secret : SecretMasker.Mask(secret, rule.KeepStart, 3), index, length));
        }

        foreach (Match m in TaiwanId.Matches(text))
        {
            var id = Compact(m.Value);
            if (id.Length != 10 || m.Value.Length - id.Length - NewlineCrCount(m.Value) > MaxIdSeparators) continue;
            if (!Checksums.IsValidTaiwanId(id)) continue;
            var resident = !(id[1] is '1' or '2');
            add(RankId, Make(resident ? SecretKind.ResidentCertificate : SecretKind.NationalId,
                resident ? "居留證號" : "身分證字號",
                SecretMasker.Mask(id.ToUpperInvariant()), m.Index, m.Length));
        }

        foreach (var (index, length, digits) in CardCandidates(text))
            add(RankCard, Make(SecretKind.CreditCard, "信用卡號", SecretMasker.Mask(digits, 4, 4), index, length));

        foreach (Match m in BusinessId.Matches(text))
        {
            var g = m.Groups[1];
            if (Checksums.IsValidBusinessId(g.Value))
                add(RankBusinessId, Make(SecretKind.BusinessId, "統一編號", SecretMasker.Mask(g.Value), g.Index, g.Length));
        }

        foreach (Match m in Mobile.Matches(text))
        {
            var digits = Digits(m.Value);
            if (digits.StartsWith("886", StringComparison.Ordinal))
                digits = "0" + digits[(digits[3] == '0' ? 4 : 3)..];
            add(RankMobile, Make(SecretKind.MobilePhone, "手機號碼", SecretMasker.Mask(digits), m.Index, m.Length));
        }
    }

    // ---------- 信用卡 ----------

    private readonly record struct Group(int Start, int End, char SepBefore);

    /// <summary>
    /// 先切出「數字組」：用單一分隔符號（空白、點、連字號、換行）接起來的一串數字，
    /// 再從裡面找連續幾組合起來是 13–19 碼、分組方式像卡號、開頭與 Luhn 都對的。
    /// 分組方式限定 4-4-4-4（最後一組 1–4 碼）、Amex 4-6-5、Diners 4-6-4，而且分隔符號要一致
    /// （換行可以取代任何一種，例如卡號在第二組後面折行）。這樣日期清單（2024-01-15 2024-02-16）、
    /// IP、版本號碼這類「數字＋分隔符號」的組合不會被硬湊成卡號。
    /// </summary>
    private static IEnumerable<(int Index, int Length, string Digits)> CardCandidates(string text)
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
                    yield return (groups[g].Start, groups[h].End - groups[g].Start, digits);
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
            '6' => (d.StartsWith("6011") || d.StartsWith("65") || P(3) is >= 644 and <= 649
                    || d.StartsWith("62")) && len is >= 16 and <= 19,                    // Discover / UnionPay
            _ => false,
        };
    }

    // ---------- 共用 ----------

    private static string Digits(string s) => new(s.Where(char.IsAsciiDigit).ToArray());

    /// <summary>去掉分隔符號，只留英數字。</summary>
    private static string Compact(string s) => new(s.Where(char.IsAsciiLetterOrDigit).ToArray());

    // \r\n 算一個分隔符號：數分隔符號時把 \r 扣掉。
    private static int NewlineCrCount(string s) => s.Count(c => c == '\r');

    /// <summary>
    /// 把下一個優先順序的結果併進已保留的清單。兩份清單都依位置排序、各自不重疊，
    /// 跟已保留的重疊就丟掉。線性時間，命中很多筆的超長文字也不會變成 O(n²)。
    /// </summary>
    private static List<SecretMatch> Merge(List<SecretMatch> kept, List<SecretMatch> next)
    {
        if (next.Count == 0) return kept;
        var result = new List<SecretMatch>(kept.Count + next.Count);
        var k = 0;
        foreach (var m in next)
        {
            while (k < kept.Count && kept[k].Index + kept[k].Length <= m.Index) result.Add(kept[k++]);
            if (k < kept.Count && kept[k].Index < m.Index + m.Length) continue;
            if (result.Count > 0 && result[^1].Index + result[^1].Length > m.Index) continue;
            result.Add(m);
        }
        while (k < kept.Count) result.Add(kept[k++]);
        return result;
    }
}
