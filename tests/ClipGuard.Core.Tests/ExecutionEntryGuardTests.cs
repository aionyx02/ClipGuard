using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class ExecutionEntryGuardTests
{
    // class / 標題 / 行程名稱都是在 Windows 11 zh-TW 實機量到的值（英文標題為對照）。
    [Theory]
    [InlineData("#32770", "執行", "explorer", EntryPoint.RunDialog)]
    [InlineData("#32770", "Run", "explorer", EntryPoint.RunDialog)]
    [InlineData("#32770", "Run", "explorer.exe", EntryPoint.RunDialog)]
    [InlineData("CabinetWClass", "Windows - 檔案總管", "explorer", EntryPoint.FileExplorer)]
    [InlineData("CabinetWClass", "Downloads - File Explorer", "explorer", EntryPoint.FileExplorer)]
    [InlineData("#32770", "開啟", "chrome", EntryPoint.FileDialog)]
    [InlineData("#32770", "Open", "msedge", EntryPoint.FileDialog)]
    [InlineData("#32770", "File Upload", "firefox", EntryPoint.FileDialog)]
    [InlineData("CASCADIA_HOSTING_WINDOW_CLASS", "Windows PowerShell 5.1", "WindowsTerminal", EntryPoint.Terminal)]
    [InlineData("CASCADIA_HOSTING_WINDOW_CLASS", @"C:\Windows\system32\cmd.exe", "WindowsTerminal", EntryPoint.Terminal)]
    [InlineData("ConsoleWindowClass", "t", "cmd", EntryPoint.Terminal)]
    [InlineData("ConsoleWindowClass", "Windows PowerShell", "powershell", EntryPoint.Terminal)]
    [InlineData("org.wezfurlong.wezterm", "pwsh", "wezterm-gui", EntryPoint.Terminal)]
    public void 認得執行入口(string cls, string title, string proc, EntryPoint expected)
    {
        Assert.Equal(expected, ExecutionEntryGuard.Classify(cls, title, proc));
    }

    [Theory]
    [InlineData("#32770", "執行", "notepad")]               // 別的程式剛好有個叫「執行」的對話框
    [InlineData("#32770", "內容", "explorer")]              // 檔案總管的其他對話框
    [InlineData("#32770", "另存新檔", "notepad")]
    [InlineData("Chrome_WidgetWin_1", "Google Chrome", "chrome")]
    [InlineData("Notepad", "未命名 - 記事本", "notepad")]
    [InlineData("Shell_TrayWnd", "", "explorer")]           // 工作列
    [InlineData("Progman", "Program Manager", "explorer")]  // 桌面
    [InlineData("CabinetWClass", "Windows - 檔案總管", "notepad")]
    [InlineData(null, null, null)]
    [InlineData("", "", "")]
    public void 一般視窗不是執行入口(string? cls, string? title, string? proc)
    {
        Assert.Equal(EntryPoint.None, ExecutionEntryGuard.Classify(cls, title, proc));
    }

    [Fact]
    public void 剪貼簿乾淨時不警告()
    {
        Assert.Null(ExecutionEntryGuard.Decide("#32770", "執行", "explorer", ThreatLevel.None, quarantined: false));
    }

    [Fact]
    public void 不是執行入口時即使剪貼簿惡意也不警告()
    {
        Assert.Null(ExecutionEntryGuard.Decide("Notepad", "記事本", "notepad", ThreatLevel.Malicious, quarantined: true));
    }

    [Fact]
    public void 可疑指令開Run提醒()
    {
        var w = ExecutionEntryGuard.Decide("#32770", "執行", "explorer", ThreatLevel.Suspicious, quarantined: false);
        Assert.NotNull(w);
        Assert.Equal(EntryPoint.RunDialog, w.Entry);
        Assert.Equal(ThreatLevel.Suspicious, w.Level);
        Assert.Contains("執行", w.Title);
    }

    [Fact]
    public void 惡意指令已清空後開Run仍提示是詐騙()
    {
        var w = ExecutionEntryGuard.Decide("#32770", "執行", "explorer", ThreatLevel.None, quarantined: true);
        Assert.NotNull(w);
        Assert.Equal(ThreatLevel.Malicious, w.Level);
        Assert.Contains("詐騙", w.Body);
        Assert.Contains("清空", w.Body);
    }

    [Fact]
    public void 惡意指令沒清掉時開終端機也警告()
    {
        var w = ExecutionEntryGuard.Decide("CASCADIA_HOSTING_WINDOW_CLASS", "PowerShell", "WindowsTerminal",
            ThreatLevel.Malicious, quarantined: false);
        Assert.NotNull(w);
        Assert.Equal(EntryPoint.Terminal, w.Entry);
        Assert.Equal(ThreatLevel.Malicious, w.Level);
    }

    [Fact]
    public void 檔案總管FileFix警告()
    {
        var w = ExecutionEntryGuard.Decide("CabinetWClass", "Windows - 檔案總管", "explorer", ThreatLevel.None, quarantined: true);
        Assert.NotNull(w);
        Assert.Equal(EntryPoint.FileExplorer, w.Entry);
        Assert.Contains("檔案總管", w.Title);
    }
}

public class EntryWarningGateTests
{
    [Fact]
    public void 同一份內容同一個視窗只警告一次()
    {
        var gate = new EntryWarningGate();
        Assert.True(gate.TryEnter(100, 1));
        Assert.False(gate.TryEnter(100, 1));
        Assert.False(gate.TryEnter(100, 1));
    }

    [Fact]
    public void 不同視窗各自警告一次()
    {
        var gate = new EntryWarningGate();
        Assert.True(gate.TryEnter(100, 1));
        Assert.True(gate.TryEnter(200, 1));
        Assert.False(gate.TryEnter(100, 1));
    }

    [Fact]
    public void 剪貼簿換內容後重新警告()
    {
        var gate = new EntryWarningGate();
        Assert.True(gate.TryEnter(100, 1));
        Assert.True(gate.TryEnter(100, 2));
        Assert.False(gate.TryEnter(100, 2));
    }
}
