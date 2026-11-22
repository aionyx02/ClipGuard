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
/// </summary>
public sealed record SecretMatch(SecretKind Kind, string Label, string Masked, int Index, int Length);

/// <summary>
/// 在任意文字裡找出常見機密格式。流程：regex 切出候選字串 → 驗檢查碼或前綴 → 遮罩。
/// 不需要使用者事先登記。
/// </summary>
public static class SecretDetector
{
    // 剪貼簿可能是一整份文件，太長的只掃前面這段，避免卡住 UI 執行緒。
    public const int MaxScanLength = 100_000;

    private const RegexOptions Opts = RegexOptions.CultureInvariant;

    // 身分證／居留證：前後不能緊鄰英數字，避免從更長的識別碼中間切出來。
    private static readonly Regex TaiwanId = new(
        @"(?<![A-Za-z0-9])[A-Za-z][1289A-Da-d]\d{8}(?![A-Za-z0-9])", Opts);

    // 統編只有 8 碼數字，且「可被 5 整除」讓約 1/5 的隨機 8 位數都會通過，
    // 單獨出現時跟日期（20231122）、訂單號碼分不出來，所以要求前面 20 字內有關鍵字。
    private static readonly Regex BusinessId = new(
        @"(?:統一編號|統編|營利事業|稅籍|VAT|Tax\s*ID)[^\d\r\n]{0,20}(?<!\d)(\d{8})(?!\d)",
        Opts | RegexOptions.IgnoreCase);

    // 13–19 碼數字，可用單一空白或連字號分隔（4-4-4-4、4-6-5 等）。
    private static readonly Regex CardCandidate = new(
        @"(?<![\d-])\d(?:[ -]?\d){12,18}(?![\d])", Opts);

    // 09 開頭 10 碼，或 +886 9xx…；允許 0912-345-678、0912 345 678。
    private static readonly Regex Mobile = new(
        @"(?<![\d+])(?:\+886[ -]?|0)9\d{2}[ -]?\d{3}[ -]?\d{3}(?!\d)", Opts);

    // key 前後不能緊鄰同類字元，以免切到更長字串的一部分。
    private const string Tail = @"(?![A-Za-z0-9_\-])";
    private const string Lead = @"(?<![A-Za-z0-9_\-])";

    // Prefix 是遮罩時保留的前綴長度（前綴本身不是機密，留著讓人看得出是哪種 key）；
    // -1 表示比對到的只有標頭（如 PEM 的 BEGIN 行），本身不含機密，原樣顯示。

    private static readonly (Regex Pattern, string Label, int Prefix)[] ApiKeys =
    [
        (new($@"{Lead}github_pat_[A-Za-z0-9_]{{22,255}}{Tail}", Opts), "GitHub token", 11),
        (new($@"{Lead}gh[pousr]_[A-Za-z0-9]{{36,255}}{Tail}", Opts), "GitHub token", 4),
        (new($@"{Lead}sk-ant-[A-Za-z0-9_\-]{{20,255}}{Tail}", Opts), "Anthropic API key", 7),
        (new($@"{Lead}sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{{20,255}}{Tail}", Opts), "API key（sk-）", 3),
        (new($@"{Lead}(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{{16,255}}{Tail}", Opts), "Stripe key", 8),
        (new(@"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])", Opts), "AWS access key", 4),
        (new($@"{Lead}xox[abposr]-[A-Za-z0-9\-]{{10,255}}{Tail}", Opts), "Slack token", 5),
        (new($@"{Lead}AIza[A-Za-z0-9_\-]{{35}}{Tail}", Opts), "Google API key", 4),
        (new($@"{Lead}glpat-[A-Za-z0-9_\-]{{20,255}}{Tail}", Opts), "GitLab token", 6),
        (new($@"{Lead}npm_[A-Za-z0-9]{{36}}{Tail}", Opts), "npm token", 4),
        (new(@"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----", Opts), "私鑰（PEM）", -1),
    ];

    public static IReadOnlyList<SecretMatch> Find(string? text)
    {
        if (string.IsNullOrEmpty(text)) return [];
        if (text.Length > MaxScanLength) text = text[..MaxScanLength];

        var found = new List<SecretMatch>();

        // 順序就是優先權：前面的類型先佔位置，後面重疊的候選會被丟掉。
        foreach (var (pattern, label, prefix) in ApiKeys)
            foreach (Match m in pattern.Matches(text))
                found.Add(new(SecretKind.ApiKey, label, prefix < 0 ? m.Value : SecretMasker.Mask(m.Value, prefix, 3), m.Index, m.Length));

        foreach (Match m in TaiwanId.Matches(text))
        {
            if (!Checksums.IsValidTaiwanId(m.Value)) continue;
            var resident = !(m.Value[1] is '1' or '2');
            found.Add(new(resident ? SecretKind.ResidentCertificate : SecretKind.NationalId,
                resident ? "居留證號" : "身分證字號",
                SecretMasker.Mask(m.Value.ToUpperInvariant()), m.Index, m.Length));
        }

        foreach (Match m in CardCandidate.Matches(text))
        {
            var digits = Digits(m.Value);
            if (IsCardPrefix(digits) && Checksums.IsValidLuhn(digits))
                found.Add(new(SecretKind.CreditCard, "信用卡號", SecretMasker.Mask(digits, 4, 4), m.Index, m.Length));
        }

        foreach (Match m in BusinessId.Matches(text))
        {
            var g = m.Groups[1];
            if (Checksums.IsValidBusinessId(g.Value))
                found.Add(new(SecretKind.BusinessId, "統一編號", SecretMasker.Mask(g.Value), g.Index, g.Length));
        }

        foreach (Match m in Mobile.Matches(text))
        {
            var digits = Digits(m.Value);
            if (digits.StartsWith("886")) digits = "0" + digits[3..];
            found.Add(new(SecretKind.MobilePhone, "手機號碼", SecretMasker.Mask(digits), m.Index, m.Length));
        }

        return RemoveOverlaps(found);
    }

    private static string Digits(string s) => new(s.Where(char.IsAsciiDigit).ToArray());

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

    private static List<SecretMatch> RemoveOverlaps(List<SecretMatch> found)
    {
        var kept = new List<SecretMatch>();
        foreach (var m in found)
            if (!kept.Any(k => m.Index < k.Index + k.Length && k.Index < m.Index + m.Length))
                kept.Add(m);
        kept.Sort((a, b) => a.Index.CompareTo(b.Index));
        return kept;
    }
}
