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
    /// <summary>電話號碼（國際格式，#27）。台灣手機另外是 <see cref="MobilePhone"/>。</summary>
    PhoneNumber,
    /// <summary>銀行帳號（IBAN，#27）。</summary>
    BankAccount,
}

/// <summary>
/// 一筆偵測結果。刻意不保留原文，只留遮罩後的字串與位置，避免結果物件被誤拿去顯示或記錄。
/// <see cref="Index"/>／<see cref="Length"/> 一律是原文（正規化之前）的位置。
/// </summary>
public sealed record SecretMatch(SecretKind Kind, string Label, string Masked, int Index, int Length);

/// <summary>
/// 在任意文字裡找出常見機密格式。流程：正規化（全形轉半形、去零寬字元）→ 規則檔（rules/*.json）的 regex 或 finder
/// 切出候選字串 → 驗檢查碼、前綴、上下文 → 遮罩 → 位置換回原文。不需要使用者事先登記。
/// 個資規則分成通用包和國家包（#27），用 <see cref="SecretPacks"/> 選要開哪些。
/// </summary>
public static class SecretDetector
{
    /// <summary>
    /// 最多分析多少字。超過時分析開頭和結尾各一半（機密常在文件頭尾，例如 .env、log 最後幾行），
    /// 中間不分析，避免在 UI 執行緒上卡住。
    /// 等於系統匣程式讀剪貼簿的上限（#24 的 ClipboardLimits.MaxAnalyzedChars），超過的部分本來就讀不到。
    /// </summary>
    public const int MaxScanLength = 1 << 20;

    // 分段分析：每段前進 SegmentStep 字，往後多看 Overlap 字、往前多看 Context 字。
    // 長度 < Overlap 的機密一定完整落在「起點所屬的那一段」裡，所以不會因為切段而漏掉或切斷。
    internal const int SegmentStep = 64 * 1024;
    internal const int Overlap = 8 * 1024;
    // 往前看的字數：notPrecededBy、上下文關鍵字（最多 32 字 + 關鍵字 24 字，見 ContextSpec）。
    private const int Context = 64;

    // 優先順序就是規則的順序（檔案 priority → 檔名 → 檔案內的順序）：前面的規則先佔位置，後面重疊的候選會被丟掉。
    private static readonly IReadOnlyList<SecretRule> Rules = SecretRules.All;

    /// <summary>用 <see cref="SecretPacks.Default"/>（通用包＋台灣包）找機密。</summary>
    public static IReadOnlyList<SecretMatch> Find(string? text) => Find(text, SecretPacks.Default);

    /// <summary>只用 <paramref name="packs"/> 裡的規則包找機密；通用包一律開啟。</summary>
    public static IReadOnlyList<SecretMatch> Find(string? text, IReadOnlySet<string> packs)
    {
        ArgumentNullException.ThrowIfNull(packs);
        if (string.IsNullOrEmpty(text)) return [];

        var active = new bool[Rules.Count];
        for (var k = 0; k < Rules.Count; k++)
            active[k] = Rules[k].Pack == SecretPacks.Universal || packs.Contains(Rules[k].Pack);

        // 每條規則各一份清單：同一條規則的結果依位置排序、互不重疊。
        var byRank = new List<SecretMatch>[Rules.Count];
        for (var r = 0; r < Rules.Count; r++) byRank[r] = [];

        foreach (var (from, to) in ScanRanges(text.Length))
        {
            for (var s = from; s < to; s += SegmentStep)
            {
                var ownedEnd = Math.Min(s + SegmentStep, to);
                var segStart = Math.Max(0, s - Context);
                var segEnd = Math.Min(text.Length, ownedEnd + Overlap);
                var norm = SecretTextNormalizer.Normalize(text, segStart, segEnd);

                FindInSegment(norm, active, (rank, match) =>
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

    private static void FindInSegment(NormalizedText norm, bool[] active, Action<int, SecretMatch> add)
    {
        var text = norm.Text;

        // 在 ASCII 版本上比對（位置不變），先用 keywords 篩掉不可能命中的規則；
        // 上下文關鍵字（可能是中日韓文字）在正規化後的文字上找（ContextSpec）。
        var ascii = SecretRules.AsciiView(text);
        var lower = ascii.ToLowerInvariant();
        string? contextLower = null;
        for (var k = 0; k < Rules.Count; k++)
        {
            if (!active[k]) continue;
            var rule = Rules[k];
            if (!rule.KeywordsPresent(lower)) continue;
            if (rule.Context is not null)
            {
                contextLower ??= ContextSpec.AsciiLower(text);
                if (!rule.Context.AnyIn(contextLower)) continue;
            }
            foreach (var (index, length, secret) in rule.Scan(ascii, text, contextLower))
            {
                var (i, l) = norm.ToOriginal(index, length);
                add(k, new(rule.Kind, rule.Label, rule.Mask(secret), i, l));
            }
        }
    }

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
