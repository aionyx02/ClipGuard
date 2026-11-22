namespace ClipGuard.Core;

/// <summary>剛複製的地址在極短時間內被換成另一個同幣別地址。</summary>
public sealed record WalletSwap(Cryptocurrency Currency, string Original, string Replacement, TimeSpan Elapsed);

/// <summary>
/// 偵測 clipper 惡意程式：它監聽剪貼簿，看到錢包地址就在幾毫秒內換成攻擊者的地址。
/// 人不可能在 0.5 秒內連續複製兩個不同地址，所以「地址 → 另一個同幣別地址」且間隔很短就警告。
/// 只保留上一次的地址和時間，存在記憶體，不寫檔。
/// </summary>
public sealed class WalletSwapDetector
{
    public static readonly TimeSpan DefaultWindow = TimeSpan.FromMilliseconds(500);

    private readonly TimeProvider _clock;
    private readonly TimeSpan _window;
    private (Cryptocurrency Currency, string Address, string Raw, DateTimeOffset At)? _last;

    public WalletSwapDetector(TimeProvider? clock = null, TimeSpan? window = null)
    {
        _clock = clock ?? TimeProvider.System;
        _window = window ?? DefaultWindow;
    }

    /// <summary>每次剪貼簿變動都呼叫一次（非文字內容傳 null）。偵測到掉包時回傳結果。</summary>
    public WalletSwap? Observe(string? text)
    {
        var now = _clock.GetUtcNow();
        if (!WalletAddress.TryParse(text, out var currency, out var address))
        {
            _last = null;
            return null;
        }

        WalletSwap? swap = null;
        if (_last is { } last && last.Currency == currency && last.Address != address)
        {
            var elapsed = now - last.At;
            if (elapsed >= TimeSpan.Zero && elapsed <= _window)
                swap = new WalletSwap(currency, last.Raw, text!.Trim(), elapsed);
        }

        _last = (currency, address, text!.Trim(), now);
        return swap;
    }
}
