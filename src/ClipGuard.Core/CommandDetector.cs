using System.Collections.Concurrent;
using System.Text;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 判斷剪貼簿文字是否為 ClickFix 類「假驗證、叫你貼上執行」的惡意指令。
/// 規則分兩類：
///   執行訊號 —— 文字會叫起可執行程式（powershell、mshta…）；
///   詐騙訊號 —— 隱藏視窗、編碼、誘餌註解、大量空白把指令擠出視線。
/// 只有執行訊號 → Suspicious（官方安裝指令也長這樣）；
/// 執行訊號 + 任一強詐騙訊號 → Malicious。「下載後直接執行」來源不是官方安裝網站時算強訊號（#20）。
/// </summary>
public static class CommandDetector
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // 含 `.*` 的規則用不回溯的引擎：同一個程式名稱重複很多次時，回溯引擎會變成 O(n²)。
    private const RegexOptions Linear = Opts | RegexOptions.NonBacktracking;

    // 這個長度以內整段一起分析（訊號可以分散在不同行）。超過時不能整段跳過（#19：
    // 惡意指令後面補空白就能繞過），改成分段分析：開頭這麼長的一段（涵蓋第一行與 Win+R 的
    // 259 字上限），再加上之後的每一行（太長的行切成重疊片段）。見 Segments。
    private const int WindowLength = 4096;

    // 分段分析的總工作量上限，避免超大剪貼簿卡住 UI 執行緒。超過上限的部分不分析。
    private const int MaxScannedChars = 256 * 1024;
    private const int MaxLines = 4000;

    // 超長文字裡，同一行連續空白最多保留這麼多個（要大於「30 個空白後接 #」的門檻）。
    private const int MaxWhitespaceRun = 64;

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
        $@"|(?:^|[;&|(])\s*{Prog(program)}(?=\s*$|\s*[|;&]|\s+#|\s+-(?:\s|$)))",
        Opts | RegexOptions.Multiline);

    private static string Prog(string program) => $@"(?:{program})(?:\.exe)?";

    /// <summary>
    /// 隱藏視窗（F3）：PowerShell 接受參數名稱的任意前綴（-w、-win、-WindowSt…，W 開頭的只有
    /// -WindowStyle；pwsh 的 -WorkingDirectory 要寫到 -wo 才分得出來），也接受 / 開頭；
    /// 值可以是名稱或數字（ProcessWindowStyle：Normal=0、Hidden=1、Minimized=2、Maximized=3）。
    /// dash 變體已由正規化換成 -。說明（CommandExplainer）共用同一個樣式。
    /// </summary>
    internal const string HiddenWindowPattern =
        @"(?:^|[\s""'])[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:le?)?)?)?)?)?)?)?)?)?(?:\s+|:)[""']?" +
        @"(?:h(?:i(?:d(?:d(?:en?)?)?)?)?|0*1)(?![\w.])";

    // ---- #21：常被 ClickFix 濫用的系統程式、遠端檔案與 protocol handler ----

    // 這些程式「後面接參數」的寫法才算（跟 Invocation 一樣），單純提到程式名稱的句子不算。
    internal static readonly Regex DelayedExpansion =
        new(@"\bcmd(?:\.exe)?\s+(?:/\S+\s+)*/v(?::on)?(?=\s|/|$)", Opts | RegexOptions.Multiline);
    internal static readonly Regex ScriptHost = new(
        @"(?:^|[\s;&|(""'])[wc]script(?:\.exe)?\s+(?:/{1,2}[a-z][\w:]*\s+)*[""']?(?://e:|[^\s""']+\.(?:vbs|vbe|js|jse|wsf|wsc|wsh)\b)",
        Opts | RegexOptions.Multiline);
    internal static readonly Regex HtmlHelp = new(
        @"(?:^|[\s;&|(""'])hh(?:\.exe)?\s+(?:-\w+\s+)*[""']?(?:https?://|\\\\|mk:@msitstore:|(?:ms-)?its:|[^\s""']+\.chm\b)",
        Opts | RegexOptions.Multiline);
    internal static readonly Regex Cmstp = new(@"\bcmstp(?:\.exe)?\s+(?:/\w+\s+)*[""']?[^\s""']+\.inf\b", Opts);
    internal static readonly Regex Pcalua = new(@"\bpcalua(?:\.exe)?\s+(?:-\w+\s+)*-a\s+\S", Opts);
    internal static readonly Regex Odbcconf = new(@"\bodbcconf(?:\.exe)?\s+[-/]\w", Opts);
    internal static readonly Regex InstallUtil =
        new(@"\binstallutil(?:\.exe)?\s+(?:[-/]\S+\s+)*[""']?[^\s""']+\.(?:dll|exe)\b", Opts);
    internal static readonly Regex FtpScript = new(@"\bftp(?:\.exe)?\s+(?:[-/]\S+\s+)*[-/]s:\S", Opts);

    // 「在下指令的位置」：行首、分隔字元後，或是會開啟／執行檔案的程式後面（可帶旗標和 start 的標題 ""）。
    // 句子裡提到的 UNC 路徑不算（P1）；單獨一行的 UNC 路徑算，因為貼進 Win+R 就會執行（同 §3.0）。
    private const string RunPosition =
        @"(?:^\s*|[;&|(]\s*|\b(?:start|explorer|call|rundll32|regsvr32|msiexec|mshta|[wc]script|pcalua|hh|powershell|pwsh|cmd|invoke-item|ii|start-process|saps)(?:\.exe)?\s+(?:[-/]\S*\s+|""""\s+)*)[""']?";
    private const string RunnableExt =
        @"\.(?:exe|lnk|bat|cmd|com|scr|pif|cpl|dll|msi|hta|ps1|vbs|vbe|js|jse|wsf|url|chm|inf|search-ms|library-ms)\b";

    // \\host\share\…\x.exe（含 \\host@SSL\DavWWWRoot\…）
    internal static readonly Regex RemoteFile = new(
        RunPosition + @"\\\\[^\s\\""'/]+\\[^\r\n""'|&;<>]*" + RunnableExt, Linear | RegexOptions.Multiline);

    // WebDAV：\\host@SSL\…、\\host@80\…、\DavWWWRoot\，出現在下指令的位置、net use 或 pushd 後面。
    internal static readonly Regex WebDav = new(
        @"(?:" + RunPosition + @"|\bnet1?(?:\.exe)?\s+use\s+(?:(?:[a-z]:|\*)\s+)?[""']?|\bpushd\s+[""']?)" +
        @"\\\\[^\s\\""'/]+(?:@(?:ssl|\d+)(?:@\d+)?(?:\\|\b)|\\davwwwroot\b)", Linear | RegexOptions.Multiline);

    // net use 掛載網路磁碟，之後從那個磁碟機代號執行檔案。代號用程式比對（NonBacktracking 不支援反向參照）。
    private static readonly Regex NetUseMap =
        new(@"\bnet1?(?:\.exe)?\s+use\s+(?<d>[a-z]:|\*)\s+[""']?\\\\", Opts);

    private static readonly ConcurrentDictionary<char, Regex> RunFromDrive = new();

    internal static bool NetUseThenRun(string text)
    {
        // 每個磁碟機代號只看第一次掛載之後的文字；樣式依代號快取，大量重複的 net use 不會一直建 Regex。
        var seen = new HashSet<char>();
        foreach (Match m in NetUseMap.Matches(text))
        {
            var drive = char.ToLowerInvariant(m.Groups["d"].Value[0]);
            if (!seen.Add(drive)) continue;
            var run = RunFromDrive.GetOrAdd(drive, d => new Regex(
                RunPosition + (d == '*' ? "[a-z]" : d.ToString()) + @":\\?[^\r\n""'|&;<>]*" + RunnableExt,
                Linear | RegexOptions.Multiline));
            if (run.IsMatch(text.AsSpan(m.Index + m.Length))) return true;
        }
        return false;
    }

    internal static readonly Regex SearchMs = new(@"\bsearch(?:-ms)?:[^\s""']*(?:query|crumb|displayname|subquery)=", Linear);
    internal static readonly Regex MsMsdt = new(@"\bms-msdt:\s*[-/]\w", Opts);

    private const string DownloadExecutionReason = "下載後直接執行";
    private const string UnofficialSourceReason = "下載並執行的來源不是已知的官方安裝網站";

    private static readonly (Regex Pattern, string Reason)[] ExecutionSignals =
    [
        (Invocation("powershell|pwsh", PowerShellArg), "呼叫 PowerShell"),
        (Invocation("mshta", MshtaArg), "呼叫 mshta（常用來執行遠端 HTA）"),
        (new(@"\bcmd(\.exe)?\s+(?:/[a-z](?::\w+)?\s*)*/[ck]\b", Opts), "呼叫 cmd 執行指令"),
        (DelayedExpansion, "cmd 延遲展開（用 !變數! 組出指令）"),
        (new(@"\bcertutil(\.exe)?\b.*-urlcache", Linear), "用 certutil 下載檔案"),
        (new(@"\bbitsadmin(\.exe)?\b.*/transfer", Linear), "用 bitsadmin 下載檔案"),
        (new(@"\brundll32(\.exe)?\b.*(javascript:|https?://)", Linear), "用 rundll32 執行腳本或遠端檔案"),
        (new(@"\bregsvr32(\.exe)?\b.*/i:\s*https?://", Linear), "用 regsvr32 載入遠端腳本"),
        (new(@"\bmsiexec(\.exe)?\b.*https?://", Linear), "用 msiexec 安裝遠端套件"),
        (new(@"\bconhost(\.exe)?\b.*--headless", Linear), "用 conhost 無視窗執行"),
        (new(@"\b(curl|wget)\b[^|]*\|\s*(ba|z)?sh\b", Opts), "下載後直接交給 shell 執行"),
        (ScriptHost, "用 wscript／cscript 執行腳本"),
        (HtmlHelp, "用 hh 開啟說明檔（可內嵌腳本）"),
        (Cmstp, "用 cmstp 安裝設定檔（可藉此執行程式）"),
        (Pcalua, "用 pcalua 間接啟動程式"),
        (Odbcconf, "用 odbcconf 載入 DLL"),
        (InstallUtil, "用 InstallUtil 執行 .NET 程式"),
        (FtpScript, "用 ftp 執行指令檔"),
        (RemoteFile, "執行網路分享（UNC／WebDAV）上的檔案"),
        (WebDav, "連到 WebDAV 遠端資料夾"),
        (SearchMs, "用 search-ms: 開啟搜尋視窗（可指向遠端資料夾）"),
        (MsMsdt, "用 ms-msdt: 呼叫疑難排解工具（Follina 手法）"),
    ];

    private static readonly (Regex Pattern, string Reason)[] ScamSignals =
    [
        (new(HiddenWindowPattern, Opts), "隱藏視窗執行"),
        (new(@"(?:^|\s)-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", Opts), "執行 Base64 編碼過的指令"),
        (new(@"\b(iex|invoke-expression)\b", Opts), "把下載內容當程式碼執行（iex）"),
        (new(@"(downloadstring|downloadfile|\biwr\b|\birm\b|invoke-webrequest|invoke-restmethod|net\.webclient)", Opts), "從網路下載內容"),
        (new(@"#.*(robot|captcha|verif|human|cloudflare|驗證|機器人|人機)", Linear), "誘餌註解（假裝是人機驗證）"),
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

        // 填充多半是空白：先把過長的空白縮短，指令前後或中間塞空白就推不出分析範圍（#19）。
        text = CollapseLongWhitespace(text);
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

    /// <summary>
    /// 把同一行內超過 <see cref="MaxWhitespaceRun"/> 個的連續空白縮成剛好這麼多個空格，換行保留。
    /// 縮完仍超過 30 個，「大量空白後接 #」的詐騙訊號不會因此消失。只掃一次，O(n)。
    /// </summary>
    internal static string CollapseLongWhitespace(string text)
    {
        var sb = new StringBuilder(Math.Min(text.Length, 1 << 20));
        var run = 0;
        foreach (var c in text)
        {
            if (c is not ('\r' or '\n') && char.IsWhiteSpace(c))
            {
                if (++run <= MaxWhitespaceRun) sb.Append(' ');
                continue;
            }
            run = 0;
            sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// 超長文字要分析的片段：開頭一段，再加上開頭那段沒完整涵蓋的每一行。
    /// 比一段還長的行切成每次前進半段的重疊片段，所以 2048 字以內的指令不管在行內哪個位置，
    /// 都會完整落在某一段裡（指令前面塞非空白字元也推不走）。
    /// </summary>
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
            // 完全落在開頭那段裡的行已經分析過了。
            if (end > WindowLength && !IsBlank(text, start, end - start))
            {
                lines++;
                for (var chunk = start; chunk < end && scanned < MaxScannedChars; chunk += WindowLength / 2)
                {
                    var length = Math.Min(end - chunk, WindowLength);
                    if (chunk + length > WindowLength)   // 整段都在開頭那段裡的就跳過
                    {
                        scanned += length;
                        yield return text.Substring(chunk, length);
                    }
                    if (chunk + length >= end) break;
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
        if (NetUseThenRun(text))
            execution.Add("掛載網路磁碟後執行裡面的檔案");

        // 下載後直接執行（#20）本身就是執行訊號：irm get.scoop.sh | iex 沒寫出程式名稱，
        // 但貼進 PowerShell 視窗就會執行。來源不在官方安裝網站清單時，再加上一個強詐騙訊號。
        var downloadExec = DownloadExecution.IsMatch(text);
        if (downloadExec)
            execution.Add(DownloadExecutionReason);
        if (execution.Count == 0)
            return Verdict.Clean;

        var scam = Matches(ScamSignals, text);
        if (downloadExec && !DownloadExecution.IsFromOfficialSource(text))
            scam.Add(UnofficialSourceReason);

        // 「從網路下載內容」「iex」單獨出現只是弱訊號：官方安裝指令（scoop、uv、bun）也長這樣。
        // 官方來源的「下載後直接執行」只提醒；要再有隱藏視窗、誘餌註解這類訊號才升級。
        var strong = scam.Where(r => r is not ("從網路下載內容" or "把下載內容當程式碼執行（iex）")).ToList();
        var level = strong.Count > 0 ? ThreatLevel.Malicious : ThreatLevel.Suspicious;

        return new Verdict(level, [.. execution, .. scam]);
    }

    private static List<string> Matches((Regex Pattern, string Reason)[] rules, string text) =>
        rules.Where(r => r.Pattern.IsMatch(text)).Select(r => r.Reason).ToList();
}
