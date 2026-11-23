using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 「下載後直接執行」（#20）：從網路抓內容，再交給 iex、PowerShell、cmd、shell 執行，
/// 或是把檔案存下來再啟動。這是 ClickFix 的核心動作，本身就足以攔截；
/// 例外是來源全部在官方安裝網站清單裡（F17），這時只提醒。
/// 只比對 <see cref="CommandNormalizer"/> 正規化後的文字。
/// </summary>
internal static class DownloadExecution
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;
    private const RegexOptions Linear = Opts | RegexOptions.NonBacktracking;

    /// <summary>
    /// 官方安裝指令會用到的網站（docs/detection-rules.md §3.2）。只比對完整主機名稱或它的子網域，
    /// 不是子字串：<c>astral.sh.example.invalid</c> 不算。清單刻意很短，
    /// 只收「官方文件叫你貼 irm … | iex 或 curl … | sh」而且網域由專案本身控制的網站；
    /// raw.githubusercontent.com 這種任何人都能放檔案的網站不能收。
    /// </summary>
    internal static readonly string[] OfficialInstallerHosts =
    [
        "astral.sh",                // uv、ruff
        "bun.sh",                   // Bun
        "get.scoop.sh", "scoop.sh", // Scoop
        "deno.land",                // Deno
        "sh.rustup.rs",             // rustup
        "get.pnpm.io",              // pnpm
        "community.chocolatey.org", // Chocolatey
        "claude.ai",                // Claude Code
        "ollama.com",               // Ollama
        "dot.net",                  // dotnet-install
        "aka.ms",                   // 微軟官方短網址（例如 install-powershell.ps1）
    ];

    private const string Fetch = @"\b(?:iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)(?:\.exe)?\b";
    private const string Interpreter = @"(?:iex|invoke-expression|powershell|pwsh|cmd|(?:ba|z)?sh)(?:\.exe)?\b";
    private const string WebClient = @"\(?\s*new-object\s+(?:system\.)?net\.webclient\b";

    // 任何形式的下載（用來搭配其他條件）。
    private static readonly Regex AnyFetch = new(
        $@"{Fetch}|download(?:string|data|file)\b|\bnet\.webclient\b|\bstart-bitstransfer\b" +
        @"|\bcertutil\b.*-urlcache|\bbitsadmin\b.*/transfer", Linear);

    // A：下載結果 pipe 給 iex 或直譯器（irm … | iex、curl … | cmd、curl … | powershell -）。
    // 下載指令後面至少要有一個參數，避免表格「| curl | cmd |」這種列舉。
    private static readonly Regex PipeToInterpreter = new(
        $@"(?:{Fetch}\s+[^\s|]|download(?:string|data)\s*\()[^\r\n]*\|\s*{Interpreter}", Linear);

    // B：iex 直接包住下載（iex(iwr …)、iex ((New-Object Net.WebClient).DownloadString(…))、iex "&{$(irm …)}"）。
    private static readonly Regex InvokeFetch = new(
        $@"\b(?:iex|invoke-expression)\b[\s(""'&{{$]*(?:{Fetch}|{WebClient}|\[(?:system\.)?net\.webclient\])", Linear);

    // C：先存進變數再 iex（$c = iwr …; iex $c）。兩個條件分開比對，避免回溯。
    private static readonly Regex AssignFetch = new(
        $@"\$[\w:]+\s*=\s*[\s(""'$]*(?:{Fetch}|{WebClient})|\$[\w:]+\s*=\s*[^\r\n;]*download(?:string|data)\s*\(", Linear);
    private static readonly Regex InvokeVariable = new(
        @"\b(?:iex|invoke-expression)\b[\s(""'&{]*\$|\$[\w:]+[^\r\n|]*\|\s*(?:iex|invoke-expression)\b", Linear);

    // D：[ScriptBlock]::Create 搭配下載。
    private static readonly Regex ScriptBlockCreate = new(@"scriptblock\]\s*::\s*create\b", Opts);

    // E：下載成檔案，再啟動它。
    private static readonly Regex SaveToFile = new(
        @"-outfile\b|\bdownloadfile\b|-urlcache\b|/transfer\b|\bstart-bitstransfer\b|(?:^|\s)(?:-o|--output|--output-document)(?:\s|=)",
        Linear | RegexOptions.Multiline);
    private static readonly Regex RunFile = new(
        @"\b(?:start-process|saps|invoke-item)\b" +
        @"|(?:^|[;&|(])\s*(?:start|call)\s+\S" +
        @"|(?:^|[;(]|&&|\|\|)\s*&\s*\S" +
        @"|(?:^|[;&|(])\s*[""']?[^\s""'|&;<>()]*\.(?:exe|bat|cmd|com|msi|scr|ps1|vbs|js|hta|lnk)\b",
        Linear | RegexOptions.Multiline);

    // 網址的主機：先抓到下一個分隔字元為止，再在 CleanHost 去掉帳號（a@b）與連接埠。
    // 反斜線也當成分隔，因為 https://evil\.astral.sh 在 .NET 裡的主機是 evil。
    private static readonly Regex UrlHost = new(@"\b(?:https?|ftp)://(?<host>[^/\s""'`)\]|;?#\\]*)", Opts);

    // 沒寫 https:// 的下載目標，例如 irm get.scoop.sh、iwr -useb get.scoop.sh。
    // 主機後面必須是分隔字元，irm astral.sh@example.invalid 這種寫法抓不到主機，就不算官方。
    private static readonly Regex BareHost = new(
        $@"{Fetch}(?:\s+-(?:usebasicparsing|useb|uri|[fsl]{{1,4}}))*\s+[""']?(?<host>[a-z0-9-]+(?:\.[a-z0-9-]+)+)(?=$|[\s/""'|;)])",
        Opts | RegexOptions.Multiline);

    private static readonly Regex AsciiHost = new(@"^[a-z0-9-]+(?:\.[a-z0-9-]+)+$", Opts);
    private static readonly Regex Port = new(@":\d*$", Opts);

    // 用字串串接、格式化、編碼組出網址時，看到的網址不可信（'https://astral.sh'+'.example.invalid'）。
    private static readonly Regex BuiltString = new(
        @"[""']\s*\+|\+\s*[""']|-join\b|\[char\]|[""']\s*-f\b|-replace\b|`|frombase64string", Opts);

    /// <summary>正規化後的文字裡，有沒有「下載後直接執行」的寫法。</summary>
    public static bool IsMatch(string text)
    {
        if (PipeToInterpreter.IsMatch(text) || InvokeFetch.IsMatch(text))
            return true;
        if (AssignFetch.IsMatch(text) && InvokeVariable.IsMatch(text))
            return true;
        if (ScriptBlockCreate.IsMatch(text) && AnyFetch.IsMatch(text))
            return true;
        return SaveToFile.IsMatch(text) && RunFile.IsMatch(text) && AnyFetch.IsMatch(text);
    }

    // 主機可能藏在這幾種行裡：下載、執行、設定變數（$u = '…'、set u=…）。
    private static readonly Regex RelevantLine = new(
        @"\b(?:iex|invoke-expression)\b|scriptblock\]|\$[\w:]+\s*=|\bset\s+""?[a-z_][\w.-]*=", Opts);

    /// <summary>
    /// 下載、執行、設定變數的那幾行裡提到的每一個主機都在官方清單裡，而且網址不是拼出來的。
    /// 變數那一行也算：免得「官方網址當幌子、真正的網址放在變數裡」。
    /// 其他行（例如 README 裡附的 GitHub 連結）不算，官方安裝指令連同說明一起複製時不會被升級。
    /// 一個主機都找不到時不放寬。
    /// </summary>
    public static bool IsFromOfficialSource(string text)
    {
        if (BuiltString.IsMatch(text)) return false;
        var relevant = string.Join("\n",
            text.Split('\n').Where(line => AnyFetch.IsMatch(line) || RelevantLine.IsMatch(line)));
        var hosts = Hosts(relevant);
        return hosts.Count > 0 && hosts.All(IsOfficialHost);
    }

    internal static bool IsOfficialHost(string host) =>
        AsciiHost.IsMatch(host) &&
        OfficialInstallerHosts.Any(o =>
            host.Equals(o, StringComparison.OrdinalIgnoreCase) ||
            host.EndsWith("." + o, StringComparison.OrdinalIgnoreCase));

    /// <summary>文字裡的下載主機（網址優先，再加上沒寫 https:// 的），小寫、不重複。</summary>
    public static List<string> Hosts(string text) =>
        UrlHost.Matches(text).Select(m => m.Groups["host"].Value)
            .Concat(BareHost.Matches(text).Select(m => m.Groups["host"].Value))
            .Select(CleanHost)
            .Where(h => h.Length > 0)
            .Distinct()
            .ToList();

    private static string CleanHost(string raw)
    {
        var at = raw.LastIndexOf('@');
        var host = at >= 0 ? raw[(at + 1)..] : raw;
        host = Port.Replace(host, "");
        return host.ToLowerInvariant().TrimEnd('.');
    }
}
