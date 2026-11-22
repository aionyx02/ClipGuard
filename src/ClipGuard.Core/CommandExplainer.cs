using System.Text;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 指令的白話說明。<see cref="DecodedCommand"/> 是 -EncodedCommand 解開後的原文（沒有則為 null）。
/// </summary>
public sealed record CommandExplanation(string? DecodedCommand, IReadOnlyList<string> Actions)
{
    public string Summary => string.Join("；", Actions);

    /// <summary>
    /// 給通知用的短文字：第一行白話，第二行解碼內容（壓成一行）。
    /// 系統匣通知的內文有長度上限，超過就截斷並加上「…」。
    /// </summary>
    public string ToDisplayText(int maxLength)
    {
        var text = "白話：" + Summary;
        if (DecodedCommand is not null)
            text += "\n解碼：" + Regex.Replace(DecodedCommand, @"\s+", " ").Trim();
        return text.Length <= maxLength ? text : text[..Math.Max(0, maxLength - 1)] + "…";
    }
}

/// <summary>
/// 把可疑指令翻成一般人看得懂的話，例如「從 evil.example 下載並執行」。
/// 只做字面分析，不執行、不連網；說明是盡力而為的提示，不是完整的語意分析。
/// </summary>
public static class CommandExplainer
{
    private const RegexOptions Opts = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant;

    // PowerShell 接受參數名稱的任意前綴，-e、-en、-enc…都是 -EncodedCommand；-ec 是官方別名。
    private static readonly Regex EncodedArg =
        new(@"(?:^|\s)-(?<name>[a-z]+)\s+[""']?(?<b64>[A-Za-z0-9+/]{8,}={0,2})", Opts);

    private static readonly Regex Url = new(@"https?://(?<host>[^/\s""'`)\]|;:?#]+)", Opts);

    // 沒寫 https:// 的下載目標，例如 irm get.scoop.sh。
    private static readonly Regex BareHost =
        new(@"\b(?:iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod)\s+[""']?(?<host>[a-z0-9-]+(?:\.[a-z0-9-]+)+)\b", Opts);

    private static readonly Regex Download =
        new(@"\b(?:iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|downloadstring|downloaddata|net\.webclient", Opts);

    private static readonly Regex Execute =
        new(@"\b(?:iex|invoke-expression)\b|\|\s*(?:powershell|pwsh|cmd|(?:ba|z)?sh)(?:\.exe)?\b", Opts);

    private static readonly Regex DownloadFile =
        new(@"downloadfile|-outfile\b|\bcertutil(?:\.exe)?\b.*-urlcache|\bbitsadmin(?:\.exe)?\b.*/transfer|\bstart-bitstransfer\b", Opts);

    private static readonly Regex Mshta = new(@"\bmshta(?:\.exe)?\b", Opts);
    private static readonly Regex Regsvr32 = new(@"\bregsvr32(?:\.exe)?\b.*/i:", Opts);
    private static readonly Regex Msiexec = new(@"\bmsiexec(?:\.exe)?\b.*https?://", Opts);
    private static readonly Regex Rundll32Script = new(@"\brundll32(?:\.exe)?\b.*javascript:", Opts);
    private static readonly Regex StartProcess = new(@"\b(?:start-process|saps)\b", Opts);
    private static readonly Regex RunAs = new(@"-verb\s+[""']?runas", Opts);

    private static readonly Regex Hidden =
        new(@"(?:^|\s)-(?:w|win|window|windowstyle)\s+[""']?(?:h|hid|hidden)\b|\bconhost(?:\.exe)?\b.*--headless", Opts);

    private static readonly Regex Bypass =
        new(@"(?:^|\s)-(?:ep|ex|exec|executionpolicy)\s+[""']?bypass\b|\bset-executionpolicy\b", Opts);

    private static readonly Regex Defender = new(@"\b(?:add|set)-mppreference\b", Opts);

    /// <summary>
    /// 找出 -EncodedCommand 的參數並以 UTF-16LE 解碼（PowerShell 的規定）。
    /// 解不開、或解出來不像文字時回傳 null。
    /// </summary>
    public static string? DecodeEncodedCommand(string? text)
    {
        var b64 = FindEncodedArg(text);
        return b64 is null ? null : TryDecode(b64);
    }

    public static CommandExplanation Explain(string text)
    {
        var encoded = FindEncodedArg(text);
        var decoded = encoded is null ? null : TryDecode(encoded);
        // 解碼內容一起分析，說明才會講到藏起來的那段。
        var all = decoded is null ? text : text + "\n" + decoded;

        var hosts = Hosts(all);
        var from = hosts.Count > 0 ? $"從 {string.Join("、", hosts)} " : "從網路";
        var actions = new List<string>();

        var downloadAndRun = Download.IsMatch(all) && Execute.IsMatch(all);
        if (downloadAndRun)
            actions.Add($"{from}下載並執行");
        if (Mshta.IsMatch(all))
            actions.Add(hosts.Count > 0 ? $"用 mshta 執行 {hosts[0]} 上的程式" : "用 mshta 執行一段腳本");
        if (Regsvr32.IsMatch(all))
            actions.Add($"{from}載入並執行遠端腳本");
        if (Msiexec.IsMatch(all))
            actions.Add($"{from}下載並安裝套件");
        if (!downloadAndRun && DownloadFile.IsMatch(all))
            actions.Add($"{from}下載檔案");
        if (Rundll32Script.IsMatch(all))
            actions.Add("用 rundll32 執行一段腳本");
        if (StartProcess.IsMatch(all))
            actions.Add(RunAs.IsMatch(all) ? "以系統管理員權限啟動其他程式" : "啟動其他程式");
        if (Hidden.IsMatch(all))
            actions.Add("隱藏視窗，執行過程你看不到");
        if (Bypass.IsMatch(all))
            actions.Add("關閉 PowerShell 的腳本安全限制");
        if (Defender.IsMatch(all))
            actions.Add("修改 Windows Defender 設定");
        if (encoded is not null)
            actions.Add(decoded is null ? "藏了一段無法解碼的編碼指令" : "藏了一段編碼過的指令");

        if (actions.Count == 0)
            actions.Add("會執行系統指令");

        return new CommandExplanation(decoded, actions);
    }

    private static string? FindEncodedArg(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        foreach (Match m in EncodedArg.Matches(text))
        {
            var name = m.Groups["name"].Value.ToLowerInvariant();
            if (name == "ec" || "encodedcommand".StartsWith(name, StringComparison.Ordinal))
                return m.Groups["b64"].Value;
        }
        return null;
    }

    private static string? TryDecode(string b64)
    {
        b64 = b64.TrimEnd('=');
        if (b64.Length % 4 == 1) return null;
        b64 = b64.PadRight(b64.Length + (4 - b64.Length % 4) % 4, '=');

        byte[] bytes;
        try { bytes = Convert.FromBase64String(b64); }
        catch (FormatException) { return null; }
        if (bytes.Length < 2 || bytes.Length % 2 != 0) return null;

        var s = Encoding.Unicode.GetString(bytes).Trim('\0', ' ', '\r', '\n', '\t');
        if (s.Length == 0) return null;

        // PowerShell 腳本絕大多數是 ASCII；拿一般 Base64（例如 UTF-8 文字）硬用 UTF-16LE 解，
        // 會變成一串罕見的 CJK 字元。可印 ASCII 不到一半就當成不是編碼指令。
        if (s.Any(c => char.IsControl(c) && c is not ('\r' or '\n' or '\t') || c == '�')) return null;
        var ascii = s.Count(c => c is >= ' ' and <= '~' or '\r' or '\n' or '\t');
        return ascii * 2 >= s.Length ? s : null;
    }

    private static List<string> Hosts(string text)
    {
        var hosts = Url.Matches(text).Select(m => m.Groups["host"].Value).ToList();
        if (hosts.Count == 0)
            hosts = BareHost.Matches(text).Select(m => m.Groups["host"].Value).ToList();
        return hosts
            .Select(h => h.ToLowerInvariant().TrimEnd('.'))
            .Distinct()
            .Take(3)
            .ToList();
    }
}
