using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class WalletAddressFindAllTests
{
    [Fact]
    public void 找出句子裡的地址與位置()
    {
        var text = $"請轉到 {Addr.Eth1}，或是 BTC：{Addr.BtcBech32}。";
        var found = WalletAddress.FindAll(text);

        Assert.Equal(2, found.Count);
        Assert.Equal(Cryptocurrency.Ethereum, found[0].Currency);
        Assert.Equal(Addr.Eth1, text.Substring(found[0].Index, found[0].Length));
        Assert.Equal(Cryptocurrency.Bitcoin, found[1].Currency);
        Assert.Equal(Addr.BtcBech32, text.Substring(found[1].Index, found[1].Length));
    }

    [Fact]
    public void 地址緊鄰中文字也找得到()
    {
        var found = WalletAddress.FindAll($"送到{Addr.Tron1}謝謝");
        Assert.Single(found);
        Assert.Equal(Cryptocurrency.Tron, found[0].Currency);
    }

    [Theory]
    [InlineData("x" + Addr.BtcGenesis)]                                  // 前面緊鄰英數字：是更長字串的一部分
    [InlineData(Addr.Eth1 + "0")]                                        // 0x + 41 hex
    [InlineData("0x5e1c5b3e84f6b1f3b0c38d9d4a8e3e1f0c2d7a9b8c6e4f2a1b3c5d7e9f0a1b2c")] // 交易 hash
    [InlineData("550e8400-e29b-41d4-a716-446655440000")]                 // UUID
    [InlineData("SGVsbG8gd29ybGQsIHRoaXMgaXMgYmFzZTY0IGRhdGE=")]          // Base64
    [InlineData("訂單編號 20261123000123456789012345，日期 2026-11-23")]
    [InlineData("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb")]                   // 檢查碼錯
    [InlineData("")]
    [InlineData(null)]
    public void 不是地址的英數字串不算(string? text)
    {
        Assert.Empty(WalletAddress.FindAll(text));
    }

    [Fact]
    public void 超長內容只掃前段而且不會卡住()
    {
        // 大量剛好落在地址長度範圍的英數字串：只驗證前 MaxCandidates 個，之後的地址不掃。
        var junk = string.Concat(Enumerable.Repeat("abcdefghijkmnopqrstuvwxyz12 ", 10_000));
        var sw = System.Diagnostics.Stopwatch.StartNew();
        Assert.Empty(WalletAddress.FindAll(junk + Addr.Eth1));
        Assert.True(sw.ElapsedMilliseconds < 2000);

        // 超過 MaxScanLength 的部分不掃。
        var text = $"{Addr.Eth1} " + new string(' ', WalletAddress.MaxScanLength) + Addr.Eth2;
        Assert.Single(WalletAddress.FindAll(text));
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
    private WalletSwapDetector NewDetector() => new(_clock);

    // 使用者在「複製 A 之後 inputAtMs 毫秒」最後一次輸入；現在是複製 A 之後 nowMs 毫秒。
    private static TimeSpan IdleSinceInputAt(int inputAtMs, int nowMs) => TimeSpan.FromMilliseconds(nowMs - inputAtMs);

    [Theory]
    [InlineData(Addr.BtcBech32, Addr.BtcBech32b)]
    [InlineData(Addr.BtcGenesis, Addr.BtcLegacy2)]
    [InlineData(Addr.BtcBech32, Addr.BtcP2sh)]          // 同幣別不同格式也算
    [InlineData(Addr.Eth1, Addr.Eth2)]
    [InlineData(Addr.Tron1, Addr.Tron2)]
    public void 短時間內換成另一個地址就警告(string original, string replacement)
    {
        var d = NewDetector();
        Assert.Null(d.Observe(original));
        _clock.Advance(30);
        var swap = d.Observe(replacement);

        Assert.NotNull(swap);
        Assert.Equal(original, swap.Original);
        Assert.Equal(replacement, swap.Replacement);
        Assert.Equal(TimeSpan.FromMilliseconds(30), swap.Elapsed);
        Assert.Equal(WalletSwapSignal.FastReplacement, swap.Signal);
    }

    [Theory]
    [InlineData(600)]
    [InlineData(800)]
    [InlineData(1000)]
    public void 一秒內被換掉就警告_即使使用者有輸入(int ms)
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(ms);
        Assert.NotNull(d.Observe(Addr.Eth2, userIdle: TimeSpan.Zero));
    }

    [Fact]
    public void 換成不同幣種也警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(50);
        var swap = d.Observe(Addr.BtcBech32);

        Assert.NotNull(swap);
        Assert.Equal(Cryptocurrency.Ethereum, swap.Currency);
        Assert.Equal(Cryptocurrency.Bitcoin, swap.ReplacementCurrency);
    }

    [Fact]
    public void 中間夾了其他內容仍然拿上一個地址比()
    {
        var d = NewDetector();
        d.Observe(Addr.BtcBech32);
        _clock.Advance(100);
        Assert.Null(d.Observe("x"));
        _clock.Advance(100);
        Assert.Null(d.Observe(null));
        _clock.Advance(100);
        var swap = d.Observe(Addr.BtcBech32b);

        Assert.NotNull(swap);
        Assert.Equal(TimeSpan.FromMilliseconds(300), swap.Elapsed);
    }

    [Fact]
    public void 超過一秒但使用者沒有任何輸入就警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(2500);
        // 最後一次輸入是複製後 200 ms（放開 Ctrl+C），之後完全沒動。
        var swap = d.Observe(Addr.Eth2, userIdle: IdleSinceInputAt(200, 2500));

        Assert.NotNull(swap);
        Assert.Equal(WalletSwapSignal.NoUserInput, swap.Signal);
    }

    [Fact]
    public void 超過一秒而且使用者有操作就不警告_刻意複製自己的兩個地址()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(1500);
        // 複製 A 之後 1.4 秒又按了鍵（複製 B 的 Ctrl+C）。
        Assert.Null(d.Observe(Addr.Eth2, userIdle: IdleSinceInputAt(1400, 1500)));
    }

    [Fact]
    public void 超過一秒但不知道輸入狀態就不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(1001);
        Assert.Null(d.Observe(Addr.Eth2));
    }

    [Fact]
    public void 剛好在寬限邊界內的輸入仍算沒有操作()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(2000);
        Assert.NotNull(d.Observe(Addr.Eth2, userIdle: IdleSinceInputAt(500, 2000)));

        var e = NewDetector();
        e.Observe(Addr.Eth1);
        _clock.Advance(2000);
        Assert.Null(e.Observe(Addr.Eth2, userIdle: IdleSinceInputAt(501, 2000)));
    }

    [Fact]
    public void 超過三秒一律不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(3001);
        Assert.Null(d.Observe(Addr.Eth2, userIdle: TimeSpan.FromMilliseconds(3001)));

        d.Observe($"send to {Addr.Eth1} please");
        _clock.Advance(3001);
        Assert.Null(d.Observe($"send to {Addr.Eth2} please"));
    }

    [Theory]
    [InlineData("send to {0} please", Addr.Eth1, Addr.Eth2)]
    [InlineData("請轉帳到{0}，謝謝", Addr.Tron1, Addr.Tron2)]
    [InlineData("BTC: {0}\nETH: " + Addr.Eth2, Addr.BtcBech32, Addr.BtcBech32b)]
    [InlineData("pay {0} now", Addr.Eth1, Addr.BtcGenesis)]                 // 句子裡換成不同幣種
    public void 句子裡只有地址被換掉就警告_即使使用者有輸入(string template, string original, string replacement)
    {
        var d = NewDetector();
        d.Observe(string.Format(template, original));
        _clock.Advance(2500);
        var swap = d.Observe(string.Format(template, replacement), userIdle: TimeSpan.Zero);

        Assert.NotNull(swap);
        Assert.Equal(WalletSwapSignal.SameSurroundingText, swap.Signal);
        Assert.Equal(original, swap.Original);
        Assert.Equal(replacement, swap.Replacement);
    }

    [Theory]
    [InlineData("send to {0} please", "my other wallet is {0}")]  // 前後文字不同：使用者複製了別段
    [InlineData("{0}", "send to {0} please")]                     // 純地址 → 句子
    [InlineData("send to {0} please", "{0}")]
    [InlineData("send to {0} please", "send to {0} please!")]
    public void 前後文字不同就不算掉包(string first, string second)
    {
        var d = NewDetector();
        d.Observe(string.Format(first, Addr.Eth1));
        _clock.Advance(10);
        Assert.Null(d.Observe(string.Format(second, Addr.Eth2), userIdle: TimeSpan.FromMilliseconds(10)));
    }

    [Fact]
    public void 含多個不同地址的合法文字不誤報()
    {
        var d = NewDetector();
        var list = $"錢包清單\nETH {Addr.Eth1}\nETH {Addr.Eth2}\nBTC {Addr.BtcBech32}";
        Assert.Null(d.Observe(list));
        _clock.Advance(10);
        Assert.Null(d.Observe(list));                     // 同一份內容再出現
        _clock.Advance(10);
        Assert.Null(d.Observe($"另一份清單\nTRON {Addr.Tron1}"));
    }

    [Fact]
    public void 地址清單只有一行被換掉也警告()
    {
        var d = NewDetector();
        d.Observe($"{Addr.Eth1}\n{Addr.BtcBech32}");
        _clock.Advance(20);
        var swap = d.Observe($"{Addr.Eth1}\n{Addr.BtcBech32b}");

        Assert.NotNull(swap);
        Assert.Equal(Addr.BtcBech32, swap.Original);
        Assert.Equal(Addr.BtcBech32b, swap.Replacement);
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
        _clock.Advance(10);
        Assert.Null(d.Observe($"send {Addr.Eth1}"));
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
    public void 時間倒退不警告()
    {
        var d = NewDetector();
        d.Observe(Addr.Eth1);
        _clock.Advance(-10);
        Assert.Null(d.Observe(Addr.Eth2));
    }

    [Fact]
    public void 時間窗常數()
    {
        Assert.Equal(TimeSpan.FromSeconds(1), WalletSwapDetector.FastWindow);
        Assert.Equal(TimeSpan.FromSeconds(3), WalletSwapDetector.Window);
        Assert.Equal(TimeSpan.FromMilliseconds(500), WalletSwapDetector.CopyInputGrace);
    }
}
