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

public class WalletSwapDetectorTests
{
    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public void Advance(int ms) => Now = Now.AddMilliseconds(ms);
    }

    private readonly FakeClock _clock = new();
    private WalletSwapDetector NewDetector(int windowMs = 500) =>
        new(_clock, TimeSpan.FromMilliseconds(windowMs));

    [Theory]
    [InlineData(Addr.BtcBech32, Addr.BtcBech32b)]
    [InlineData(Addr.BtcGenesis, Addr.BtcLegacy2)]
    [InlineData(Addr.BtcBech32, Addr.BtcP2sh)]          // 同幣別不同格式也算
    [InlineData(Addr.Eth1, Addr.Eth2)]
    [InlineData(Addr.Tron1, Addr.Tron2)]
    public void 短時間內換成另一個同幣別地址就警告(string original, string replacement)
    {
        var d = NewDetector();
        Assert.Null(d.Observe(original));
        _clock.Advance(30);
        var swap = d.Observe(replacement);

        Assert.NotNull(swap);
        Assert.Equal(original, swap.Original);
        Assert.Equal(replacement, swap.Replacement);
        Assert.Equal(TimeSpan.FromMilliseconds(30), swap.Elapsed);
    }

    [Fact]
    public void 剛好在時間窗邊界內仍警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(500);
        Assert.NotNull(d.Observe(Addr.Eth2));
    }

    [Fact]
    public void 超過時間窗不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(501);
        Assert.Null(d.Observe(Addr.Eth2));
    }

    [Fact]
    public void 時間窗可設定()
    {
        var d = NewDetector(windowMs: 2000);
        d.Observe(Addr.Eth1);
        _clock.Advance(1500);
        Assert.NotNull(d.Observe(Addr.Eth2));
    }

    [Fact]
    public void 同一個地址再出現不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(10);
        Assert.Null(d.Observe(Addr.Eth1.ToLowerInvariant()));   // 只差大小寫，同一地址
        _clock.Advance(10);
        Assert.Null(d.Observe(" " + Addr.Eth1.ToLowerInvariant() + "\n"));
    }

    [Fact]
    public void 不同幣別不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.BtcBech32);
        _clock.Advance(10);
        Assert.Null(d.Observe(Addr.Eth1));
    }

    [Fact]
    public void 中間夾了非地址內容就重新計算()
    {
        var d = NewDetector();
        d.Observe(Addr.BtcBech32);
        _clock.Advance(10);
        d.Observe("hello");
        _clock.Advance(10);
        Assert.Null(d.Observe(Addr.BtcBech32b));
        _clock.Advance(10);
        d.Observe(null);
        _clock.Advance(10);
        Assert.Null(d.Observe(Addr.BtcBech32));
    }

    [Fact]
    public void 無效檢查碼的假地址不觸發()
    {
        var d = NewDetector();
        d.Observe(Addr.BtcGenesis);
        _clock.Advance(10);
        Assert.Null(d.Observe("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"));
    }

    [Fact]
    public void 連續掉包每次都警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(10);
        Assert.NotNull(d.Observe(Addr.Eth2));
        _clock.Advance(10);
        Assert.NotNull(d.Observe(Addr.Eth1));
    }

    [Fact]
    public void 預設時間窗為500毫秒()
    {
        Assert.Equal(TimeSpan.FromMilliseconds(500), WalletSwapDetector.DefaultWindow);
        var d = new WalletSwapDetector(_clock);
        d.Observe(Addr.Eth1);
        _clock.Advance(499);
        Assert.NotNull(d.Observe(Addr.Eth2));
    }
}
