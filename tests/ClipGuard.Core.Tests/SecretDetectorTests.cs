using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class SecretDetectorTests
{
    // API key 樣本在執行時才組起來，避免原始碼被 secret scanning 誤認為外洩的 token。
    private static string Fake(string prefix, int n, char c = 'a') => prefix + new string(c, n);

    private static SecretMatch Single(string text) => Assert.Single(SecretDetector.Find(text));

    [Fact]
    public void 從句子中找出身分證並遮罩()
    {
        var m = Single("我的身分證是A123456789，請幫我填表");
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("A12****789", m.Masked);
        Assert.Equal(6, m.Index);
        Assert.Equal(10, m.Length);
    }

    [Theory]
    [InlineData("居留證 A800000014")]
    [InlineData("ARC: AB12345677")]
    public void 居留證(string text) => Assert.Equal(SecretKind.ResidentCertificate, Single(text).Kind);

    [Theory]
    [InlineData("A123456788")]            // 檢查碼錯
    [InlineData("XA123456789")]           // 前面黏著字母，是更長識別碼的一部分
    [InlineData("A1234567890")]           // 後面多一碼
    public void 檢查碼錯或邊界不對不算身分證(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.NationalId);

    [Theory]
    [InlineData("卡號 4111 1111 1111 1111 到期 12/30", "4111********1111")]
    [InlineData("4111-1111-1111-1111", "4111********1111")]
    [InlineData("amex 378282246310005", "3782*******0005")]
    [InlineData("5555555555554444", "5555********4444")]
    [InlineData("3530111333300000", "3530********0000")]
    public void 信用卡(string text, string masked)
    {
        var m = Single(text);
        Assert.Equal(SecretKind.CreditCard, m.Kind);
        Assert.Equal(masked, m.Masked);
    }

    [Theory]
    [InlineData("4111111111111112")]       // Luhn 錯
    [InlineData("1234567812345670")]       // Luhn 對但不是任何發卡組織開頭
    [InlineData("訂單編號 9999999999999995")]
    public void 不是信用卡(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.CreditCard);

    [Theory]
    [InlineData("手機 0912345678", "091****678")]
    [InlineData("0912-345-678", "091****678")]
    [InlineData("0912 345 678", "091****678")]
    [InlineData("+886912345678", "091****678")]
    [InlineData("+886 912-345-678", "091****678")]
    public void 手機(string text, string masked)
    {
        var m = Single(text);
        Assert.Equal(SecretKind.MobilePhone, m.Kind);
        Assert.Equal(masked, m.Masked);
    }

    [Theory]
    [InlineData("091234567")]      // 9 碼
    [InlineData("09123456789")]    // 11 碼
    [InlineData("0812345678")]     // 不是 09
    public void 不是手機(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.MobilePhone);

    [Theory]
    [InlineData("統一編號：12345675", "12****75")]
    [InlineData("統編 24680241", "24****41")]
    [InlineData("VAT No. 13579134", "13****34")]
    public void 統編要有關鍵字(string text, string masked)
    {
        var m = Single(text);
        Assert.Equal(SecretKind.BusinessId, m.Kind);
        Assert.Equal(masked, m.Masked);
    }

    [Theory]
    [InlineData("12345675")]                // 沒有關鍵字：8 位數太容易誤判（日期、訂單號）
    [InlineData("統一編號：12345678")]      // 檢查碼錯
    public void 不算統編(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.BusinessId);

    public static TheoryData<string, string> ApiKeys => new()
    {
        { Fake("ghp_", 36), "GitHub token" },
        { Fake("gho_", 36), "GitHub token" },
        { Fake("github_pat_", 82, 'B'), "GitHub token" },
        { Fake("sk-ant-api03-", 40), "Anthropic API key" },
        { Fake("sk-proj-", 40), "API key（sk-）" },
        { Fake("sk-", 48), "API key（sk-）" },
        { Fake("AKIA", 16, 'Q'), "AWS access key" },
        { Fake("xoxb-", 30, '1'), "Slack token" },
        { Fake("AIza", 35), "Google API key" },
        { Fake("glpat-", 20), "GitLab token" },
        { Fake("sk_live_", 24), "Stripe key" },
        { Fake("npm_", 36), "npm token" },
    };

    [Theory]
    [MemberData(nameof(ApiKeys))]
    public void API_key前綴(string key, string label)
    {
        var m = Single($"export TOKEN=\"{key}\"\n");
        Assert.Equal(SecretKind.ApiKey, m.Kind);
        Assert.Equal(label, m.Label);
        Assert.DoesNotContain(key, m.Masked);
        Assert.Contains('*', m.Masked);
    }

    [Fact]
    public void 私鑰標頭()
    {
        var m = Single("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----");
        Assert.Equal("私鑰（PEM）", m.Label);
        Assert.DoesNotContain("b3Bl", m.Masked);
    }

    [Theory]
    [InlineData("sk-short")]                       // 太短
    [InlineData("risk-assessment-document-final")] // sk- 在單字中間
    [InlineData("AKIAshort")]
    [InlineData("ghp_tooShort123")]
    public void 不像API_key(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.ApiKey);

    [Fact]
    public void 一段文字裡多種機密依位置排序()
    {
        var text = $"姓名王小明 身分證 A123456789 手機 0912-345-678 卡號 4111111111111111 token {Fake("ghp_", 36)}";
        var kinds = SecretDetector.Find(text).Select(m => m.Kind).ToArray();
        Assert.Equal([SecretKind.NationalId, SecretKind.MobilePhone, SecretKind.CreditCard, SecretKind.ApiKey], kinds);
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    [InlineData("明天下午三點開會，地點在 3 樓")]
    [InlineData("https://example.com/item/20231122")]
    [InlineData("版本 1.2.3，build 123456")]
    public void 一般文字沒有結果(string? text) => Assert.Empty(SecretDetector.Find(text));

    [Fact]
    public void 遮罩結果從不包含完整原文()
    {
        var samples = new[] { "A123456789", "0912345678", "4111111111111111", Fake("ghp_", 36), "統編 12345675" };
        foreach (var s in samples)
        {
            var m = Assert.Single(SecretDetector.Find(s));
            var original = s.Substring(m.Index, m.Length);
            Assert.DoesNotContain(original, m.Masked);
            Assert.Contains("*", m.Masked);
        }
    }
}
