using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// 地址取自公開資料（創世區塊、BIP-173/350 範例、Bitcoin Wiki、USDT-TRC20 合約、以太坊基金會）。
internal static class Addr
{
    public const string BtcGenesis = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    public const string BtcLegacy2 = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";
    public const string BtcP2sh = "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy";
    public const string BtcBech32 = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    public const string BtcBech32b = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh";
    public const string BtcBech32P2wsh = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3";
    public const string BtcTaproot = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0";
    public const string Eth1 = "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe";
    public const string Eth2 = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
    public const string Tron1 = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";
    public const string Tron2 = "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7";
}

public class WalletAddressTests
{
    [Theory]
    [InlineData(Addr.BtcGenesis, Cryptocurrency.Bitcoin)]
    [InlineData(Addr.BtcLegacy2, Cryptocurrency.Bitcoin)]
    [InlineData(Addr.BtcP2sh, Cryptocurrency.Bitcoin)]
    [InlineData(Addr.BtcBech32, Cryptocurrency.Bitcoin)]
    [InlineData(Addr.BtcBech32P2wsh, Cryptocurrency.Bitcoin)]
    [InlineData(Addr.BtcTaproot, Cryptocurrency.Bitcoin)]
    [InlineData("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ", Cryptocurrency.Bitcoin)] // 全大寫有效
    [InlineData(Addr.Eth1, Cryptocurrency.Ethereum)]
    [InlineData("0x0000000000000000000000000000000000000000", Cryptocurrency.Ethereum)]
    [InlineData(Addr.Tron1, Cryptocurrency.Tron)]
    [InlineData("  " + Addr.BtcGenesis + "\r\n", Cryptocurrency.Bitcoin)]          // 前後空白可接受
    public void 辨識有效地址(string text, Cryptocurrency expected)
    {
        Assert.True(WalletAddress.TryParse(text, out var currency, out _));
        Assert.Equal(expected, currency);
    }

    [Theory]
    [InlineData("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")]              // 檢查碼錯
    [InlineData("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLz")]
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdp")]      // bech32 檢查碼錯
    [InlineData("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwF5mdq")]      // 大小寫混用
    [InlineData("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj1")]
    [InlineData("TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6u")]
    [InlineData("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BA")]       // 少一位
    [InlineData("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAg")]      // 非 hex
    [InlineData("送到 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")]           // 不是整段都是地址
    [InlineData("A123456789")]
    [InlineData("")]
    [InlineData(null)]
    public void 拒絕無效或非地址(string? text)
    {
        Assert.False(WalletAddress.TryParse(text, out _, out _));
    }
}
