using System.Text;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 比對指令規則前的正規化：把 cmd / PowerShell 會「當成同一件事」的寫法還原成最單純的形式，
/// 讓 <see cref="CommandDetector"/> 的規則只需要認得 <c>mshta https://…</c> 這種寫法（#19）。
/// 純函式：不讀環境變數、不碰檔案系統；輸出只拿來比對，原文另外保留給顯示與還原。
///
/// 處理的寫法（依序）：
///   1. dash 變體（U+2010–2015、U+2212、U+FE58、U+FE63、U+FF0D）→ <c>-</c>
///   2. cmd 的 <c>^</c> 跳脫：<c>m^s^h^t^a</c> → <c>mshta</c>，<c>^^</c> → <c>^</c>，行尾 <c>^</c> 接行
///   3. <c>set x=…</c> / <c>set "x=…"</c> 之後的 <c>%x%</c> 代入（只代入一層，次數有上限）
///   4. 常見系統環境變數：<c>%SystemRoot%</c>、<c>%windir%</c>、<c>%ComSpec%</c>、<c>%ProgramFiles%</c>…，
///      以及 PowerShell 的 <c>$env:windir</c> 寫法
///   5. 用引號拆開的字：<c>"m"sh"ta"</c>、<c>ms""hta</c> → <c>mshta</c>
///   6. 已知程式的完整路徑只留檔名：<c>"C:\…\System32\mshta.exe"</c> → <c>mshta</c>
/// 沒處理的寫法見 docs/detection-rules.md §3.4。
/// </summary>
public static class CommandNormalizer
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // 規則會比對的程式；完整路徑只對這些程式縮成檔名，其他路徑（例如 C:\x\a.ps1）保持原樣，
    // 免得把「powershell C:\x\tool.exe」這類原本就靠路徑判斷的寫法弄丟。新增規則時一起加進來。
    private const string KnownPrograms =
        "powershell|pwsh|mshta|cmd|certutil|bitsadmin|rundll32|regsvr32|msiexec|conhost|curl|wget";

    // set 代入的上限：避免 %a%%a%%a%… 把短字串放大成很長的文字。
    private const int MaxVariables = 16;
    private const int MaxValueLength = 1024;
    private const int MaxExpansions = 64;

    private static readonly Dictionary<string, string> KnownEnv = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SystemRoot"] = @"C:\Windows",
        ["windir"] = @"C:\Windows",
        ["SystemDrive"] = "C:",
        ["ComSpec"] = @"C:\Windows\System32\cmd.exe",
        ["ProgramFiles"] = @"C:\Program Files",
        ["ProgramW6432"] = @"C:\Program Files",
        ["ProgramFiles(x86)"] = @"C:\Program Files (x86)",
        ["CommonProgramFiles"] = @"C:\Program Files\Common Files",
    };

    private static readonly Regex CaretNewline = new(@"\^\r?\n", Opts);
    private static readonly Regex Caret = new(@"\^(.)", Opts | RegexOptions.Singleline);

    private static readonly Regex SetQuoted =
        new(@"(?<=^|[\s&|(;])set\s+""(?<n>[a-z_][\w.#$@-]*)=(?<v>[^""\r\n]*)""", Opts | RegexOptions.Multiline);
    private static readonly Regex SetPlain =
        new(@"(?<=^|[\s&|(;])set\s+(?<n>[a-z_][\w.#$@-]*)=(?<v>[^&|\r\n""]*)", Opts | RegexOptions.Multiline);

    private static readonly Regex PercentVar = new(@"%(?<n>[^%\s""]{1,64})%", Opts);
    private static readonly Regex PsEnvVar = new(@"\$env:(?<n>[a-z_][\w]*(?:\(x86\))?)", Opts);

    // 字中間的引號：a"bc"d、ab""c。只收單字字元，不會吃掉 -c "iex(…)" 這種真正的字串參數。
    private static readonly Regex QuoteAfterWord = new(@"(?<=\w)""(?<w>\w*)""", Opts);
    private static readonly Regex QuoteBeforeWord = new(@"""(?<w>\w*)""(?=\w)", Opts);

    // 加引號的路徑可以有空白，所以必須是明確的路徑開頭（磁碟代號、UNC、相對路徑），
    // 否則 -c "Get-Item C:\x\cmd" 這種字串參數會被誤吃。只有程式名稱也算（"mshta"）。
    private static readonly Regex QuotedPath = new(
        $@"""(?:(?:[a-z]:|\\\\|\.{{1,2}})[\\/](?:[^""\r\n]*[\\/])?)?(?<p>{KnownPrograms})(?:\.exe)?""", Opts);

    // 沒有引號的路徑：一個不含空白的 token，最後一段是已知程式。
    private static readonly Regex PlainPath = new(
        $@"(?<=^|[\s;&|(=,'""])(?<dir>[^\s""'|&;<>()]*[\\/])(?<p>{KnownPrograms})(?:\.exe)?(?=$|[\s""'|&;<>()])",
        Opts | RegexOptions.Multiline);

    private static readonly Regex WindowsDrivePath = new(@"^(?:[a-z]:|\\\\)", Opts);

    public static string Normalize(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var s = NormalizeDashes(text);
        s = CaretNewline.Replace(s, "");
        s = Caret.Replace(s, "$1");
        s = ExpandVariables(s);
        s = CollapseSplitQuotes(s);
        s = QuotedPath.Replace(s, "${p}");
        s = PlainPath.Replace(s, StripDirectory);
        return s;
    }

    private static bool IsDash(char c) =>
        c is >= '\u2010' and <= '\u2015' or '\u2212' or '\uFE58' or '\uFE63' or '\uFF0D';

    private static string NormalizeDashes(string s)
    {
        if (!s.Any(IsDash)) return s;
        var sb = new StringBuilder(s.Length);
        foreach (var c in s) sb.Append(IsDash(c) ? '-' : c);
        return sb.ToString();
    }

    private static string ExpandVariables(string s)
    {
        var vars = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var re in new[] { SetQuoted, SetPlain })
        {
            foreach (Match m in re.Matches(s))
            {
                if (vars.Count >= MaxVariables) break;
                var value = m.Groups["v"].Value.TrimEnd();
                if (value.Length <= MaxValueLength) vars[m.Groups["n"].Value] = value;
            }
        }

        var budget = MaxExpansions;
        string Lookup(Match m)
        {
            var name = m.Groups["n"].Value;
            if (budget <= 0) return m.Value;
            if (vars.TryGetValue(name, out var v) || KnownEnv.TryGetValue(name, out v))
            {
                budget--;
                return v;
            }
            return m.Value;
        }

        s = PercentVar.Replace(s, Lookup);
        return PsEnvVar.Replace(s, m => KnownEnv.TryGetValue(m.Groups["n"].Value, out var v) ? v : m.Value);
    }

    private static string CollapseSplitQuotes(string s)
    {
        if (!s.Contains('"')) return s;
        // "m"sh"ta" 要兩輪才會變成 "mshta"，之後交給 QuotedPath 拿掉外層引號。
        for (var i = 0; i < 8; i++)
        {
            var next = QuoteBeforeWord.Replace(QuoteAfterWord.Replace(s, "${w}"), "${w}");
            if (next == s) break;
            s = next;
        }
        return s;
    }

    private static string StripDirectory(Match m)
    {
        var dir = m.Groups["dir"].Value;
        // 網址（https://x/mshta）和只用 / 的相對路徑（github.com/powershell/powershell）不是 Windows 路徑。
        if (dir.Contains("://")) return m.Value;
        if (!dir.Contains('\\') && !WindowsDrivePath.IsMatch(dir)) return m.Value;
        return m.Groups["p"].Value;
    }
}
