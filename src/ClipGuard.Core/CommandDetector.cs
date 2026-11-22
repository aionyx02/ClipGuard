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

    // 這個長度以內整段一起分析（訊號可以分散在不同行）。超過時不能整段跳過（#19：
    // 惡意指令後面補空白就能繞過），改成分段分析：開頭這麼長的一段（涵蓋第一行與 Win+R 的
    // 259 字上限），再加上之後的每一行（每行同樣只看前這麼長）。
    private const int WindowLength = 4096;

    // 分段分析的總工作量上限，避免超大剪貼簿卡住 UI 執行緒。超過上限的部分不分析。
    private const int MaxScannedChars = 256 * 1024;
    private const int MaxLines = 4000;

    // 程式名稱後面「像參數」的東西：-x 或 /x 參數、引號、註解、變數、腳本區塊、呼叫運算子。
    private const string CommonArg = @"[-/][a-z?]|[""'#$&({\[]";

    // PowerShell 直接接指令的寫法（powershell iwr …）：後面要是 cmdlet、常見別名或腳本路徑，
    // 而不是任意英文單字，否則 "I use powershell every day" 也會被當成指令（#8）。
    private const string PowerShellArg =
        @"(?:iwr|irm|iex|saps|curl|wget)\b" +
        @"|(?:invoke|start|stop|new|set|get|add|remove|copy|move|out|write|import|expand|register|enable|disable)-[a-z]" +
        @"|\.{1,2}[\\/]|[a-z]:\\|\S+\.ps1\b";

    // mshta 的參數是要執行的網址、vbscript:/javascript: 或 .hta 檔。
    private const string MshtaArg = @"(?:https?://|vbscript:|javascript:|about:)|\S+\.hta\b";

    // 程式名稱要「像在下指令」：位於開頭或分隔符號後，且後面接參數。
    // 什麼都不接時（例如 `curl … | powershell`），前面必須是開頭或管線／分隔符號，
    // 避免把網址路徑（github.com/powershell）或一般句子（我在學 PowerShell、I use powershell）當成指令。
    private static Regex Invocation(string program, string arg) => new(
        $@"(?:(?:^|[\s;&|(""']){Prog(program)}(?=\s+(?:{CommonArg}|{arg}))" +
        $@"|(?:^|[;&|(])\s*{Prog(program)}(?=\s*$|\s*[|;&]|\s+#))",
        Opts | RegexOptions.Multiline);

    private static string Prog(string program) => $@"(?:{program})(?:\.exe)?";

    private static readonly (Regex Pattern, string Reason)[] ExecutionSignals =
    [
        (Invocation("powershell|pwsh", PowerShellArg), "呼叫 PowerShell"),
        (Invocation("mshta", MshtaArg), "呼叫 mshta（常用來執行遠端 HTA）"),
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
        (new(@"(?<!\s)\s{30,}#", Opts), "用大量空白把真正的指令擠出輸入框"),
        (new(@"\bmshta(\.exe)?\s+[""']?https?://", Opts), "mshta 直接執行遠端網址"),
    ];

    public static Verdict Analyze(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return Verdict.Clean;
        if (text.Length <= WindowLength)
            return AnalyzeSegment(text);

        // 分段結果取最高等級；理由依出現順序合併、不重複。
        var level = ThreatLevel.None;
        var reasons = new List<string>();
        foreach (var segment in Segments(text))
        {
            var v = AnalyzeSegment(segment);
            if (v.Level == ThreatLevel.None) continue;
            if (v.Level > level) level = v.Level;
            foreach (var r in v.Reasons)
                if (!reasons.Contains(r)) reasons.Add(r);
        }
        return level == ThreatLevel.None ? Verdict.Clean : new Verdict(level, reasons);
    }

    /// <summary>超長文字要分析的片段：開頭一段，再加上開頭那段沒完整涵蓋的每一行。</summary>
    internal static IEnumerable<string> Segments(string text)
    {
        yield return text[..WindowLength];

        var scanned = WindowLength;
        var lines = 0;
        var start = 0;
        while (start < text.Length && scanned < MaxScannedChars && lines < MaxLines)
        {
            var end = text.IndexOf('\n', start);
            if (end < 0) end = text.Length;
            // 完全落在開頭那段裡的行已經分析過了；第一行截斷後就是開頭那段本身。
            if (end > WindowLength && start > 0)
            {
                var length = Math.Min(end - start, WindowLength);
                if (!IsBlank(text, start, length))
                {
                    lines++;
                    scanned += length;
                    yield return text.Substring(start, length);
                }
            }
            start = end + 1;
        }
    }

    private static bool IsBlank(string text, int start, int length)
    {
        for (var i = start; i < start + length; i++)
            if (!char.IsWhiteSpace(text[i])) return false;
        return true;
    }

    private static Verdict AnalyzeSegment(string raw)
    {
        // 規則只比對正規化後的文字（完整路徑、^、引號拆字、dash 變體…），原文由呼叫端保留。
        var text = CommandNormalizer.Normalize(raw);

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
