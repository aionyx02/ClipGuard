using System.Security.Cryptography;
using System.Text;

namespace ClipGuard.Core;

/// <summary>判定掉包所依據的訊號（決定了能接受多長的間隔，見 docs/detection-rules.md §6.2）。</summary>
public enum WalletSwapSignal
{
    /// <summary>間隔短到不可能是人連續複製兩次（≤ <see cref="WalletSwapDetector.FastWindow"/>）。</summary>
    FastReplacement,
    /// <summary>前後文字完全相同，只有地址變了（句子裡的地址被換掉）。</summary>
    SameSurroundingText,
    /// <summary>複製地址之後使用者沒有任何鍵盤或滑鼠動作，剪貼簿卻變了。</summary>
    NoUserInput,
}

/// <summary>
/// 剛複製的地址被換成另一個地址。Original / Replacement 只給測試與除錯用，通知一律不顯示（P4）。
/// </summary>
public sealed record WalletSwap(
    Cryptocurrency Currency,
    Cryptocurrency ReplacementCurrency,
    string Original,
    string Replacement,
    TimeSpan Elapsed,
    WalletSwapSignal Signal);

/// <summary>
/// 偵測 clipper 惡意程式：它監聽剪貼簿，看到錢包地址就換成攻擊者的地址（常常只換句子裡的那一段）。
/// 只記住最後一次看到地址的那份內容（地址、去掉地址後的文字的 SHA-256、時間），存在記憶體，不寫檔。
///
/// 判定（前後兩份內容去掉地址後的文字必須完全相同，只有地址不同）：
///   - 有前後文字（句子裡的地址）：<see cref="Window"/> 內就警告；
///   - 只有地址：<see cref="FastWindow"/> 內警告；超過但仍在 <see cref="Window"/> 內，
///     只有在複製之後使用者完全沒有輸入時才警告。
/// 中間夾了不含地址的內容（A → "x" → B）不會重新計算。
/// </summary>
public sealed class WalletSwapDetector
{
    /// <summary>只有地址、而且沒有其他訊號時，這個間隔內被換掉就警告。人不可能在 1 秒內選取並複製兩個不同地址。</summary>
    public static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(1);

    /// <summary>記住上一個地址的最長時間；有前後文字或「沒有輸入」的訊號時，這個間隔內被換掉都警告。</summary>
    public static readonly TimeSpan Window = TimeSpan.FromSeconds(3);

    /// <summary>
    /// 複製當下的按鍵（放開 Ctrl、C）會在剪貼簿變動後陸續送到；這段時間內的輸入算是「複製 A」的一部分，
    /// 不算使用者之後又做了什麼。
    /// </summary>
    public static readonly TimeSpan CopyInputGrace = TimeSpan.FromMilliseconds(500);

    private readonly TimeProvider _clock;

    private sealed record Snapshot(WalletAddressMatch[] Addresses, string[] Raw, byte[] TemplateHash, bool HasContext, DateTimeOffset At);

    private Snapshot? _last;

    public WalletSwapDetector(TimeProvider? clock = null) => _clock = clock ?? TimeProvider.System;

    /// <summary>
    /// 每次剪貼簿變動都呼叫一次（非文字內容傳 null）。偵測到掉包時回傳結果。
    /// </summary>
    /// <param name="userIdle">
    /// 現在距離使用者最後一次鍵盤或滑鼠輸入多久（Windows 的 GetLastInputInfo）；不知道就傳 null，
    /// 這時「只有地址」的情況只用 <see cref="FastWindow"/> 判斷。
    /// </param>
    public WalletSwap? Observe(string? text, TimeSpan? userIdle = null)
    {
        var now = _clock.GetUtcNow();
        var addresses = WalletAddress.FindAll(text);
        // 不含地址的內容不改變記憶：A → "x" → B 仍然拿 A 來比。
        if (addresses.Count == 0) return null;

        var current = Capture(text!, addresses, now);
        var last = _last;
        _last = current;
        if (last is null) return null;

        var elapsed = now - last.At;
        if (elapsed < TimeSpan.Zero || elapsed > Window) return null;

        // clipper 用取代的方式換地址，前後文字一個字都不會變；前後文字不同就是使用者複製了別的東西。
        if (!last.TemplateHash.AsSpan().SequenceEqual(current.TemplateHash)
            || last.Addresses.Length != current.Addresses.Length) return null;

        var changed = -1;
        for (var i = 0; i < current.Addresses.Length && changed < 0; i++)
            if (current.Addresses[i].Normalized != last.Addresses[i].Normalized) changed = i;
        if (changed < 0) return null;

        WalletSwapSignal? signal =
            current.HasContext ? WalletSwapSignal.SameSurroundingText
            : elapsed <= FastWindow ? WalletSwapSignal.FastReplacement
            : userIdle is { } idle && now - idle <= last.At + CopyInputGrace ? WalletSwapSignal.NoUserInput
            : null;
        if (signal is null) return null;

        return new WalletSwap(
            last.Addresses[changed].Currency, current.Addresses[changed].Currency,
            last.Raw[changed], current.Raw[changed], elapsed, signal.Value);
    }

    private static Snapshot Capture(string text, IReadOnlyList<WalletAddressMatch> addresses, DateTimeOffset at)
    {
        // 去掉地址後的文字（地址換成佔位字元，頭尾空白不算），只留 hash，不留原文。
        var template = new StringBuilder(text.Length);
        var pos = 0;
        var raw = new string[addresses.Count];
        for (var i = 0; i < addresses.Count; i++)
        {
            var a = addresses[i];
            template.Append(text, pos, a.Index - pos).Append('\uFFFC');
            raw[i] = text.Substring(a.Index, a.Length);
            pos = a.Index + a.Length;
        }
        template.Append(text, pos, text.Length - pos);
        var trimmed = template.ToString().Trim();

        var hasContext = trimmed.Any(c => c != '\uFFFC' && !char.IsWhiteSpace(c));
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(trimmed));
        return new Snapshot([.. addresses], raw, hash, hasContext, at);
    }
}
