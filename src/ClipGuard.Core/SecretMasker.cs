namespace ClipGuard.Core;

/// <summary>把機密遮成「A12****789」這種形式，用在通知、清單等任何要顯示給人看的地方。</summary>
public static class SecretMasker
{
    // 星號最多顯示幾個：長 API key 不需要把幾十個星號都印出來，也不透露確切長度。
    private const int MaxStars = 8;
    // 至少遮住幾個字元。10 碼身分證保留頭尾各 3 碼 → A12****789。
    private const int MinHidden = 4;

    /// <summary>
    /// 頭尾各保留幾個字元，中間換成星號。
    /// 保留字元數會隨長度縮減，確保至少 MinHidden 個字元被遮住；太短的字串全部遮住。
    /// </summary>
    public static string Mask(string value, int keepStart = 3, int keepEnd = 3)
    {
        if (string.IsNullOrEmpty(value)) return "";

        var maxKeep = Math.Max(0, value.Length - MinHidden);
        while (keepStart + keepEnd > maxKeep && (keepStart > 0 || keepEnd > 0))
        {
            // 先縮尾端：開頭通常是前綴或類別資訊，比尾端更不敏感。
            if (keepEnd >= keepStart && keepEnd > 0) keepEnd--;
            else keepStart--;
        }

        var hidden = value.Length - keepStart - keepEnd;
        return string.Concat(
            value.AsSpan(0, keepStart),
            new string('*', Math.Min(hidden, MaxStars)),
            value.AsSpan(value.Length - keepEnd));
    }
}
