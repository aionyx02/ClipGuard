using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class HiddenCharDetectorTests
{
    private static Verdict A(string? text) => HiddenCharDetector.Analyze(text);

    [Theory]
    [InlineData("git\u200B push")]
    [InlineData("pass\u200Cword")]
    [InlineData("rm -rf\u200D /tmp/x")]
    [InlineData("sudo\u2060 apt update")]
    [InlineData("\uFEFFnpm install")]
    public void 零寬字元判為可疑(string text)
    {
        var v = A(text);
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains(v.Reasons, r => r.Contains("零寬字元"));
    }

    [Theory]
    [InlineData("👨\u200D👩\u200D👧\u200D👦")]           // 家庭 emoji
    [InlineData("🏳\uFE0F\u200D🌈 驕傲旗")]
    [InlineData("👩🏽\u200D💻 寫程式")]                    // 膚色 + ZWJ
    [InlineData("❤\uFE0F\u200D🔥")]
    [InlineData("می\u200Cخواهم")]                         // 波斯文 ZWNJ
    [InlineData("क्\u200Dष")]                              // 天城文 ZWJ
    public void 正常的連接字元不算零寬攻擊(string text)
    {
        Assert.Equal(ThreatLevel.None, A(text).Level);
    }

    [Theory]
    [InlineData("if (isAdmin) { \u202E } \u2066// check later\u2069 {")]
    [InlineData("access_level != \"user\u202E \u2066// Check if admin\u2069 \u2066\"")]
    [InlineData("abc\u202Adef")]
    [InlineData("abc\u202Bdef")]
    [InlineData("abc\u202Cdef")]
    [InlineData("abc\u202Ddef")]
    [InlineData("abc\u2067def")]
    [InlineData("abc\u2068def")]
    public void Bidi控制字元判為可疑(string text)
    {
        var v = A(text);
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains(v.Reasons, r => r.Contains("Bidi"));
    }

    [Theory]
    [InlineData("powersh\u0435ll -c whoami", '\u0435')]          // 西里爾 е
    [InlineData("curl https://\u0430pple.com/install.sh", '\u0430')] // 西里爾 а
    [InlineData("git clone https://github.c\u043Em/x/y", '\u043E')]  // 西里爾 о
    [InlineData("np\u03BFde index.js", '\u03BF')]                 // 希臘 ο
    [InlineData("echo ѕоѕ", 'ѕ')]            // 整個字都是同形字：ѕоѕ
    [InlineData("ping һоѕt", 'һ')]           // 同形字加英文 t：һоѕt
    public void 英文裡混入同形字判為可疑(string text, char glyph)
    {
        var v = A(text);
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains(v.Reasons, r => r.Contains($"U+{(int)glyph:X4}"));
    }

    [Theory]
    [InlineData("Привет, как дела? Это обычный русский текст.")]
    [InlineData("Я использую Linux и команду git каждый день.")]   // 俄文夾英文單字
    [InlineData("Καλημέρα, τι κάνεις;")]
    [InlineData("圓周長 = 2πr，面積 = πr²")]
    [InlineData("Δx 和 μm 是常見符號")]
    public void 合法的西里爾希臘文字不誤判(string text)
    {
        Assert.Equal(ThreatLevel.None, A(text).Level);
    }

    [Theory]
    [InlineData("git pull\n")]
    [InlineData("sudo apt update\r\n")]
    [InlineData("$ npm install\n")]
    [InlineData("PS C:\\> Remove-Item foo; powershell -c whoami\n")]
    [InlineData("cd repo\nmake install\n")]
    [InlineData("./install.sh\n")]
    [InlineData("git commit -m \"修正錯誤\"\n")]
    public void 指令結尾換行判為可疑(string text)
    {
        var v = A(text);
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains(v.Reasons, r => r.Contains("結尾有換行"));
    }

    [Theory]
    [InlineData("git pull")]                 // 沒有換行
    [InlineData("明天下午三點開會\n")]
    [InlineData("Hello world\n")]
    [InlineData("git 是版本控制工具\n")]
    [InlineData("\n\n")]
    public void 非指令或沒有結尾換行不提醒(string text)
    {
        Assert.Equal(ThreatLevel.None, A(text).Level);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("明天下午三點開會，記得帶筆電。")]
    [InlineData("今日は良い天気ですね。カタカナもひらがなも大丈夫。")]
    [InlineData("한국어 텍스트입니다")]
    [InlineData("全形英數ＡＢＣ１２３與標點，。！")]
    [InlineData("powershell -c \"irm https://get.scoop.sh | iex\"")]
    [InlineData("Café naïve résumé")]
    public void 一般文字判為乾淨(string? text)
    {
        Assert.Equal(ThreatLevel.None, A(text).Level);
    }

    [Fact]
    public void 多種問題同時列出()
    {
        var v = A("p\u0430ss\u200Bwd\n");
        Assert.Equal(ThreatLevel.Suspicious, v.Level);
        Assert.Contains(v.Reasons, r => r.Contains("零寬字元"));
        Assert.Contains(v.Reasons, r => r.Contains("U+0430"));
    }

    [Fact]
    public void 理由不包含原文()
    {
        var v = A("secret-t\u043Eken-12345\u200B");
        Assert.All(v.Reasons, r => Assert.DoesNotContain("12345", r));
    }
}
