using System.Text;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 指令的白話說明。<see cref="DecodedCommand"/> 是 -EncodedCommand 解開後的原文（沒有則為 null）。
/// </summary>
public sealed record CommandExplanation(string? DecodedCommand, IReadOnlyList<string> Actions)
{
    public string Summary => string.Join(CoreStrings.Explain_ActionSeparator, Actions);

    /// <summary>
    /// 給通知用的短文字：第一行白話，第二行解碼內容（壓成一行）。
    /// 系統匣通知的內文有長度上限，超過就截斷並加上「…」。
    /// </summary>
    public string ToDisplayText(int maxLength)
    {
        var text = CoreStrings.Explain_Display(Summary);
        if (DecodedCommand is not null)
            text += "\n" + CoreStrings.Explain_Decoded(Regex.Replace(DecodedCommand, @"\s+", " ").Trim());
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

    private static readonly Regex Download =
        new(@"\b(?:iwr|irm|curl|wget|invoke-webrequest|invoke-restmethod|start-bitstransfer)\b|downloadstring|downloaddata|net\.webclient", Opts);

    private static readonly Regex Execute =
        new(@"\b(?:iex|invoke-expression)\b|\|\s*(?:powershell|pwsh|cmd|(?:ba|z)?sh)(?:\.exe)?\b|scriptblock\]\s*::\s*create\b", Opts);

    // UNC 路徑的主機：\\host\share、\\host@SSL\DavWWWRoot。
    private static readonly Regex UncHost = new(@"\\\\(?<host>[^\s\\""'/@]+)", Opts);

    private static readonly Regex DownloadFile =
        new(@"downloadfile|-outfile\b|\bcertutil(?:\.exe)?\b.*-urlcache|\bbitsadmin(?:\.exe)?\b.*/transfer|\bstart-bitstransfer\b", Opts);

    private static readonly Regex Mshta = new(@"\bmshta(?:\.exe)?\b", Opts);
    private static readonly Regex Regsvr32 = new(@"\bregsvr32(?:\.exe)?\b.*/i:", Opts);
    private static readonly Regex Msiexec = new(@"\bmsiexec(?:\.exe)?\b.*https?://", Opts);
    private static readonly Regex Rundll32Script = new(@"\brundll32(?:\.exe)?\b.*javascript:", Opts);
    private static readonly Regex StartProcess = new(@"\b(?:start-process|saps)\b", Opts);
    private static readonly Regex RunAs = new(@"-verb\s+[""']?runas", Opts);

    private static readonly Regex Hidden =
        new($@"{CommandDetector.HiddenWindowPattern}|\bconhost(?:\.exe)?\b.*--headless", Opts);

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

    // 說明只看開頭這麼長（正規化後的文字），避免超大剪貼簿拖慢通知。
    private const int MaxExplainLength = 4096;

    public static CommandExplanation Explain(string text)
    {
        // 跟偵測一樣先正規化，完整路徑、^、引號拆字、dash 變體的寫法才說明得出來（#19）。
        text = CommandNormalizer.Normalize(text.Length > MaxExplainLength ? text[..MaxExplainLength] : text);
        var encoded = FindEncodedArg(text);
        var decoded = encoded is null ? null : TryDecode(encoded);
        // 解碼內容一起分析，說明才會講到藏起來的那段。
        var all = decoded is null ? text : text + "\n" + decoded;

        var hosts = Hosts(all);
        var from = hosts.Count > 0
            ? CoreStrings.Explain_SourceHosts(string.Join(CoreStrings.ListSeparator, hosts))
            : CoreStrings.Explain_SourceInternet;
        var actions = new List<string>();

        var downloadAndRun = Download.IsMatch(all) && Execute.IsMatch(all) || DownloadExecution.IsMatch(all);
        if (downloadAndRun)
            actions.Add(CoreStrings.Explain_DownloadAndRun(from));
        if (Mshta.IsMatch(all))
            actions.Add(hosts.Count > 0 ? CoreStrings.Explain_MshtaHost(hosts[0]) : CoreStrings.Explain_MshtaScript);
        if (Regsvr32.IsMatch(all))
            actions.Add(CoreStrings.Explain_Regsvr32(from));
        if (Msiexec.IsMatch(all))
            actions.Add(CoreStrings.Explain_Msiexec(from));
        if (!downloadAndRun && DownloadFile.IsMatch(all))
            actions.Add(CoreStrings.Explain_DownloadFile(from));
        if (Rundll32Script.IsMatch(all))
            actions.Add(CoreStrings.Explain_Rundll32);
        AddLolbinActions(all, actions);
        if (StartProcess.IsMatch(all))
            actions.Add(RunAs.IsMatch(all) ? CoreStrings.Explain_StartProcessAdmin : CoreStrings.Explain_StartProcess);
        if (Hidden.IsMatch(all))
            actions.Add(CoreStrings.Explain_Hidden);
        if (Bypass.IsMatch(all))
            actions.Add(CoreStrings.Explain_Bypass);
        if (Defender.IsMatch(all))
            actions.Add(CoreStrings.Explain_Defender);
        if (encoded is not null)
            actions.Add(decoded is null ? CoreStrings.Explain_EncodedUndecodable : CoreStrings.Explain_Encoded);

        if (actions.Count == 0)
            actions.Add(CoreStrings.Explain_Generic);

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

    // #21 的系統程式、遠端檔案與 protocol handler。樣式跟偵測共用，說明跟判斷不會對不上。
    private static void AddLolbinActions(string text, List<string> actions)
    {
        var share = UncHost.Match(text) is { Success: true } m ? m.Groups["host"].Value.ToLowerInvariant() : null;

        if (CommandDetector.DelayedExpansion.IsMatch(text))
            actions.Add(CoreStrings.Explain_DelayedExpansion);
        if (CommandDetector.ScriptHost.IsMatch(text))
            actions.Add(CoreStrings.Explain_ScriptHost);
        if (CommandDetector.HtmlHelp.IsMatch(text))
            actions.Add(CoreStrings.Explain_HtmlHelp);
        if (CommandDetector.Cmstp.IsMatch(text))
            actions.Add(CoreStrings.Explain_Cmstp);
        if (CommandDetector.Pcalua.IsMatch(text))
            actions.Add(CoreStrings.Explain_Pcalua);
        if (CommandDetector.Odbcconf.IsMatch(text))
            actions.Add(CoreStrings.Explain_Odbcconf);
        if (CommandDetector.InstallUtil.IsMatch(text))
            actions.Add(CoreStrings.Explain_InstallUtil);
        if (CommandDetector.FtpScript.IsMatch(text))
            actions.Add(CoreStrings.Explain_FtpScript);
        if (CommandDetector.RemoteFile.IsMatch(text))
            actions.Add(share is null ? CoreStrings.Explain_RemoteFile : CoreStrings.Explain_RemoteFileHost(share));
        else if (CommandDetector.WebDav.IsMatch(text))
            actions.Add(share is null ? CoreStrings.Explain_WebDav : CoreStrings.Explain_WebDavHost(share));
        if (CommandDetector.NetUseThenRun(text))
            actions.Add(CoreStrings.Explain_NetUse);
        if (CommandDetector.SearchMs.IsMatch(text))
            actions.Add(CoreStrings.Explain_SearchMs);
        if (CommandDetector.MsMsdt.IsMatch(text))
            actions.Add(CoreStrings.Explain_MsMsdt);
    }

    private static List<string> Hosts(string text) => DownloadExecution.Hosts(text).Take(3).ToList();
}
