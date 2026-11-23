using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class SecretRegistrationTests
{
    // 明顯是假的測試字串。
    private const string Fake = "fake-secret-123";

    [Fact]
    public void 兩次輸入一致且長度合法就通過() =>
        Assert.Null(SecretRegistration.Validate(Fake, Fake));

    [Theory]
    [InlineData("", "")]
    [InlineData(null, null)]
    [InlineData("", "abcdef")]
    public void 機密空白時標在機密欄(string? secret, string? confirm)
    {
        var e = SecretRegistration.Validate(secret, confirm);
        Assert.Equal(RegistrationField.Secret, e?.Field);
    }

    [Theory]
    [InlineData(5)]
    [InlineData(257)]
    public void 長度不合法時標在機密欄並說明範圍(int length)
    {
        var s = new string('x', length);
        var e = SecretRegistration.Validate(s, s);
        Assert.Equal(RegistrationField.Secret, e?.Field);
        Assert.Contains($"{RegisteredSecretStore.MinLength}–{RegisteredSecretStore.MaxLength}", e!.Message);
    }

    [Theory]
    [InlineData(6)]
    [InlineData(256)]
    public void 長度邊界值可以登記(int length)
    {
        var s = new string('x', length);
        Assert.Null(SecretRegistration.Validate(s, s));
    }

    [Fact]
    public void 確認欄空白時標在確認欄() =>
        Assert.Equal(RegistrationField.Confirm, SecretRegistration.Validate(Fake, "")?.Field);

    [Fact]
    public void 兩次不一致時標在確認欄() =>
        Assert.Equal(RegistrationField.Confirm, SecretRegistration.Validate(Fake, Fake + "x")?.Field);

    [Fact]
    public void 錯誤訊息不含輸入內容()
    {
        var e = SecretRegistration.Validate(Fake, Fake + "x");
        Assert.DoesNotContain(Fake, e!.Message);
    }
}
