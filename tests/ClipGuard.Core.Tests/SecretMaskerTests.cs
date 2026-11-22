using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class SecretMaskerTests
{
    [Theory]
    [InlineData("A123456789", "A12****789")]
    [InlineData("0912345678", "091****678")]
    [InlineData("12345675", "12****75")]
    [InlineData("abcde", "a****")]
    [InlineData("abcd", "****")]
    [InlineData("", "")]
    public void 預設保留頭尾(string value, string expected) => Assert.Equal(expected, SecretMasker.Mask(value));

    [Fact]
    public void 長字串星號有上限且不含原文()
    {
        var key = "ghp_" + new string('x', 36);
        var masked = SecretMasker.Mask(key, 4, 3);
        Assert.Equal("ghp_********xxx", masked);
        Assert.DoesNotContain(key, masked);
    }

    [Theory]
    [InlineData("A123456789")]
    [InlineData("4111111111111111")]
    [InlineData("abcdef")]
    public void 至少遮住四個字元(string value)
    {
        var masked = SecretMasker.Mask(value, 10, 10);
        Assert.True(masked.Count(c => c == '*') >= 4);
        Assert.NotEqual(value, masked);
    }
}
