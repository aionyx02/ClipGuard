namespace ClipGuard.Core;

/// <summary>剪貼簿內容的讀取上限（#24 F20）。</summary>
public static class ClipboardLimits
{
    /// <summary>
    /// 複製時最多讀進來分析的字數（UTF-16 char），超過的部分不讀、不分析。
    ///
    /// 1 Mi 字（約 2 MB）是所有偵測器各自上限的好幾倍，所以截斷不會讓偵測變弱：
    /// <list type="bullet">
    /// <item>指令偵測縮完空白後最多看 256 Ki 字、4000 行（<c>CommandDetector.MaxScannedChars</c>），
    /// 截斷前還留了約 768 Ki 字給空白、空行這類不計入的填充。</item>
    /// <item>機密偵測最多 100,000 字、登記的機密最多 20,000 字、隱藏字元超過 100,000 字就不看。</item>
    /// </list>
    /// 這是唯一的讀取上限；調高任何偵測器的長度上限時（例如 #22），不要超過這個值，超過的部分根本讀不到。
    /// 被清空的指令另外讀完整內容存進隔離區，還原時不會少一截。
    /// </summary>
    public const int MaxAnalyzedChars = 1 << 20;

    /// <summary>截到 <see cref="MaxAnalyzedChars"/> 字時實際保留幾個字：不把代理對切成一半。</summary>
    public static int CutLength(ReadOnlySpan<char> text)
    {
        if (text.Length <= MaxAnalyzedChars) return text.Length;
        var length = MaxAnalyzedChars;
        return char.IsHighSurrogate(text[length - 1]) ? length - 1 : length;
    }

    /// <summary>跟 App 從剪貼簿讀進來的結果一樣的前綴。</summary>
    public static string Prefix(string text) => text.Length <= MaxAnalyzedChars ? text : text[..CutLength(text)];
}
