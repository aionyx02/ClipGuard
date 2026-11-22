namespace ClipGuard.Core;

/// <summary>使用者可以「貼上就執行」的地方。</summary>
public enum EntryPoint
{
    None,
    /// <summary>Win+R 執行視窗。</summary>
    RunDialog,
    /// <summary>檔案總管（FileFix：叫你在網址列貼上）。</summary>
    FileExplorer,
    /// <summary>瀏覽器等程式叫出的「開啟」檔案對話框（FileFix 也會用它的網址列）。</summary>
    FileDialog,
    /// <summary>Windows Terminal、conhost 的 cmd / PowerShell 等終端機。</summary>
    Terminal,
}

public sealed record EntryWarning(EntryPoint Entry, ThreatLevel Level, string Title, string Body);

/// <summary>
/// 判斷前景視窗是不是執行入口，以及剪貼簿狀態下要不要再警告一次。
/// 純函式：輸入是視窗 class、標題、行程名稱（不含 .exe）和剪貼簿判定，不碰 Win32。
/// </summary>
/// <remarks>
/// 檔案總管只看前景視窗是否為 CabinetWClass，不偵測網址列是否取得焦點：
/// 網址列焦點在 Windows 11 是 XAML 島（InputSiteWindowClass），跟檔案清單分不清楚，
/// 而且使用者常常先開檔案總管再按 Ctrl+L，等到焦點進網址列才警告可能已經太晚。
/// 剪貼簿裡剛好有可疑指令又打開檔案總管的情況很少，提早警告的代價不高。
/// </remarks>
public static class ExecutionEntryGuard
{
    private const StringComparison Ci = StringComparison.OrdinalIgnoreCase;

    // 實測 Windows 11 zh-TW：Run 對話框 class=#32770、標題「執行」、行程 explorer。
    private static readonly string[] RunDialogTitles = ["執行", "Run", "运行"];

    // 實測 zh-TW 的通用開啟對話框標題為「開啟」；Firefox 上傳時用「上傳檔案」/「File Upload」。
    private static readonly string[] FileDialogTitles =
        ["開啟", "開啟檔案", "上傳檔案", "選擇要上傳的檔案", "Open", "Open File", "File Upload", "Choose File to Upload", "打开"];

    // 實測：Windows Terminal=CASCADIA_HOSTING_WINDOW_CLASS，conhost=ConsoleWindowClass，WezTerm=org.wezfurlong.wezterm。
    private static readonly string[] TerminalClasses =
        ["CASCADIA_HOSTING_WINDOW_CLASS", "ConsoleWindowClass", "org.wezfurlong.wezterm", "mintty"];

    // conhost 視窗用 GetWindowThreadProcessId 查到的是 cmd / powershell 本身，不是 conhost。
    private static readonly string[] TerminalProcesses =
        ["WindowsTerminal", "wezterm-gui", "alacritty", "mintty", "powershell_ise"];

    public static EntryPoint Classify(string? className, string? title, string? processName)
    {
        className ??= "";
        title = (title ?? "").Trim();
        processName = (processName ?? "").Trim();
        if (processName.EndsWith(".exe", Ci)) processName = processName[..^4];

        var isExplorer = processName.Equals("explorer", Ci);

        if (className == "#32770")
        {
            if (isExplorer && RunDialogTitles.Any(t => t.Equals(title, Ci)))
                return EntryPoint.RunDialog;
            if (FileDialogTitles.Any(t => t.Equals(title, Ci)))
                return EntryPoint.FileDialog;
            return EntryPoint.None;
        }

        if (isExplorer && className is "CabinetWClass" or "ExploreWClass")
            return EntryPoint.FileExplorer;

        if (TerminalClasses.Any(c => c.Equals(className, Ci)) || TerminalProcesses.Any(p => p.Equals(processName, Ci)))
            return EntryPoint.Terminal;

        return EntryPoint.None;
    }

    /// <param name="currentLevel">目前剪貼簿內容的判定。</param>
    /// <param name="quarantined">剛攔截並清空過惡意指令，且使用者之後還沒複製別的東西。</param>
    /// <returns>不需要警告時為 null。</returns>
    public static EntryWarning? Decide(string? className, string? title, string? processName,
        ThreatLevel currentLevel, bool quarantined)
    {
        var entry = Classify(className, title, processName);
        if (entry == EntryPoint.None) return null;

        var where = entry switch
        {
            EntryPoint.RunDialog => "「執行」視窗",
            EntryPoint.FileExplorer => "檔案總管",
            EntryPoint.FileDialog => "檔案對話框",
            _ => "終端機",
        };

        if (quarantined || currentLevel == ThreatLevel.Malicious)
            return new EntryWarning(entry, ThreatLevel.Malicious,
                $"小心！你剛打開了{where}",
                (quarantined ? "剛才攔截的指令已從剪貼簿清空。" : "剪貼簿裡有惡意指令。")
                + "\n叫你按 Win+R、開檔案總管或終端機貼上指令的「驗證」是詐騙手法，請直接關掉。");

        if (currentLevel == ThreatLevel.Suspicious)
            return new EntryWarning(entry, ThreatLevel.Suspicious,
                $"你打開了{where}，剪貼簿裡有會執行程式的指令",
                "貼上前請確認指令來源可信。網站要你貼上指令「完成驗證」一定是詐騙。");

        return null;
    }
}

/// <summary>
/// 同一份剪貼簿內容，對同一個視窗只警告一次，避免切來切去一直跳通知。
/// 剪貼簿內容一換（generation 不同）就重新計算。
/// </summary>
public sealed class EntryWarningGate
{
    private long _generation = long.MinValue;
    private readonly HashSet<nint> _warned = [];

    public bool TryEnter(nint window, long clipboardGeneration)
    {
        if (clipboardGeneration != _generation)
        {
            _generation = clipboardGeneration;
            _warned.Clear();
        }
        return _warned.Add(window);
    }
}
