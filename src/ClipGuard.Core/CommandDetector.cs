using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 判斷剪貼簿文字是否為 ClickFix 類「假驗證、叫你貼上執行」的惡意指令。
/// 規則分兩類：
///   執行訊號 —— 文字會叫起可執行程式（powershell、mshta…）；
///   詐騙訊號 —— 隱藏視窗、編碼、誘餌註解、大量空白把指令擠出視線。
/// 只有執行訊號 → Suspicious（官方安裝指令也長這樣）；
/// 執行訊號 + 任一詐騙訊號 → Malicious。
/// </summary>
public static class CommandDetector
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // 超過這個長度幾乎不可能是要貼進 Win+R 的一行指令（Win+R 上限 259 字元，留寬鬆空間）。
    private const int MaxLength = 4096;

    // 程式名稱要「像在下指令」：位於開頭或分隔符號後，且後面接參數、引號、註解或結尾。
    // 避免把網址路徑（github.com/powershell）或一般句子（我在學 PowerShell）當成指令。
    private static Regex Invocation(string program) => new(
        $@"(?:^|[\s;&|(""'])(?:{program})(?:\.exe)?(?=\s+[-/""'#a-z0-9]|\s*$|\s*[|;&])",
        Opts | RegexOptions.Multiline);

    private static readonly (Regex Pattern, string Reason)[] ExecutionSignals =
    [
        (Invocation("powershell|pwsh"), "呼叫 PowerShell"),
        (Invocation("mshta"), "呼叫 mshta（常用來執行遠端 HTA）"),
        (new(@"\bcmd(\.exe)?\s+/[ck]\b", Opts), "呼叫 cmd 執行指令"),
        (new(@"\bcertutil(\.exe)?\b.*-urlcache", Opts), "用 certutil 下載檔案"),
        (new(@"\bbitsadmin(\.exe)?\b.*/transfer", Opts), "用 bitsadmin 下載檔案"),
        (new(@"\brundll32(\.exe)?\b.*(javascript:|https?://)", Opts), "用 rundll32 執行腳本或遠端檔案"),
        (new(@"\bregsvr32(\.exe)?\b.*/i:\s*https?://", Opts), "用 regsvr32 載入遠端腳本"),
        (new(@"\bmsiexec(\.exe)?\b.*https?://", Opts), "用 msiexec 安裝遠端套件"),
        (new(@"\bconhost(\.exe)?\b.*--headless", Opts), "用 conhost 無視窗執行"),
        (new(@"\b(curl|wget)\b[^|]*\|\s*(ba|z)?sh\b", Opts), "下載後直接交給 shell 執行"),
    ];

    private static readonly (Regex Pattern, string Reason)[] ScamSignals =
    [
        (new(@"(?:^|\s)-(w|win|window|windowstyle)\s+(h|hid|hidden)\b", Opts), "隱藏視窗執行"),
        (new(@"(?:^|\s)-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", Opts), "執行 Base64 編碼過的指令"),
        (new(@"\b(iex|invoke-expression)\b", Opts), "把下載內容當程式碼執行（iex）"),
        (new(@"(downloadstring|downloadfile|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|net\.webclient)", Opts), "從網路下載內容"),
        (new(@"#.*(robot|captcha|verif|human|cloudflare|驗證|機器人|人機)", Opts), "誘餌註解（假裝是人機驗證）"),
        (new(@"[✅✔☑]", Opts), "含勾選符號（假驗證常見）"),
        (new(@"\s{30,}#", Opts), "用大量空白把真正的指令擠出輸入框"),
        (new(@"\bmshta(\.exe)?\s+[""']?https?://", Opts), "mshta 直接執行遠端網址"),
    ];

    public static Verdict Analyze(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || text.Length > MaxLength)
            return Verdict.Clean;

        var execution = Matches(ExecutionSignals, text);
        if (execution.Count == 0)
            return Verdict.Clean;

        var scam = Matches(ScamSignals, text);

        // 「從網路下載內容」單獨出現仍可能是合法安裝指令（如 irm get.scoop.sh | iex 會同時命中 iex），
        // 所以下載 + iex 這組只算 Suspicious，要再有其他詐騙訊號才升級。
        var strong = scam.Where(r => r is not ("從網路下載內容" or "把下載內容當程式碼執行（iex）")).ToList();
        var level = strong.Count > 0 ? ThreatLevel.Malicious : ThreatLevel.Suspicious;

        return new Verdict(level, [.. execution, .. scam]);
    }

    private static List<string> Matches((Regex Pattern, string Reason)[] rules, string text) =>
        rules.Where(r => r.Pattern.IsMatch(text)).Select(r => r.Reason).ToList();
}
