using System.Runtime.InteropServices;
using ClipGuard.Core;

namespace ClipGuard.App;

/// <summary>剪貼簿讀寫。剪貼簿可能正被別的程式開著，所有操作都短暫重試幾次。</summary>
internal static class ClipboardAccess
{
    // 告訴 Windows 剪貼簿歷程記錄（Win+V）與雲端剪貼簿不要收錄這次寫入。
    private const string ExcludeFromHistory = "ExcludeClipboardContentFromMonitorProcessing";

    private static readonly string[] TextFormats =
        [DataFormats.UnicodeText, DataFormats.Text, DataFormats.OemText, DataFormats.Rtf, DataFormats.Html, DataFormats.CommaSeparatedValue];

    public static T? Retry<T>(Func<T> action)
    {
        for (var i = 0; i < 5; i++)
        {
            try { return action(); }
            catch (ExternalException) { Thread.Sleep(30); }
        }
        return default;
    }

    /// <summary>讀完整的文字。只在使用者要貼遮罩版、或要隔離超長指令時用；複製時的分析改用 <see cref="TryGetTextPrefix"/>。</summary>
    public static string? TryGetText() =>
        Retry(() => Clipboard.ContainsText() ? Clipboard.GetText() : null);

    /// <summary>
    /// 只讀前 <see cref="ClipboardLimits.MaxAnalyzedChars"/> 字（#24 F20）。直接從 CF_UNICODETEXT 的記憶體複製需要的那一段，
    /// 不經過 WinForms／OLE：那條路會把整段內容複製好幾份，5 MB 的內容峰值約 250 MB。
    /// </summary>
    /// <returns>沒有文字時為 null；<c>Truncated</c> 表示後面還有沒讀的內容。</returns>
    public static (string Text, bool Truncated)? TryGetTextPrefix() =>
        Retry(ReadTextPrefix);

    private static (string Text, bool Truncated)? ReadTextPrefix()
    {
        const int maxChars = ClipboardLimits.MaxAnalyzedChars;
        if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return null;
        // 被別的程式開著時丟 ExternalException，讓 Retry 等一下再試。
        if (!OpenClipboard(IntPtr.Zero)) throw new ExternalException("OpenClipboard", Marshal.GetLastWin32Error());
        try
        {
            var handle = GetClipboardData(CF_UNICODETEXT);
            if (handle == IntPtr.Zero) return null;
            var ptr = GlobalLock(handle);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                // 多讀一個字，才分得出「剛好 maxChars 字」和「後面還有」。
                var available = (long)(ulong)GlobalSize(handle) / sizeof(char);
                var count = (int)Math.Min(available, maxChars + 1L);
                var buffer = new char[count];
                Marshal.Copy(ptr, buffer, 0, count);
                var length = Array.IndexOf(buffer, '\0');
                if (length < 0) length = count;
                var truncated = length > maxChars;
                if (truncated) length = ClipboardLimits.CutLength(buffer.AsSpan(0, length));
                return (new string(buffer, 0, length), truncated);
            }
            finally { GlobalUnlock(handle); }
        }
        finally { CloseClipboard(); }
    }

    public static void TryClear() => Retry(() => { Clipboard.Clear(); return true; });

    public static bool TrySetText(string text) => Retry(() => { Clipboard.SetText(text); return true; });

    /// <summary>剪貼簿序號；內容每換一次就會變，讀取不會。</summary>
    public static uint SequenceNumber => GetClipboardSequenceNumber();

    /// <summary>
    /// 把剪貼簿裡的文字類格式（純文字、RTF、HTML…）複製一份到記憶體，用來在「貼遮罩版」後還原。
    /// 圖片、檔案等其他格式不保留：會走到這裡的剪貼簿一定是含機密的文字。
    /// </summary>
    public static DataObject? TrySaveTextFormats() => Retry(() =>
    {
        var src = Clipboard.GetDataObject();
        if (src is null) return null;
        var copy = new DataObject();
        foreach (var f in TextFormats)
        {
            if (!src.GetDataPresent(f, autoConvert: false)) continue;
            if (src.GetData(f, autoConvert: false) is string s) copy.SetData(f, autoConvert: false, s);
        }
        return copy.GetFormats(autoConvert: false).Length == 0 ? null : copy;
    });

    /// <summary>寫入剪貼簿並排除在剪貼簿歷程記錄之外（遮罩版與還原的原文都不必再多一筆歷程）。</summary>
    public static bool TrySet(DataObject data)
    {
        data.SetData(ExcludeFromHistory, autoConvert: false, new MemoryStream(new byte[4]));
        return Retry(() => { Clipboard.SetDataObject(data, copy: true); return true; });
    }

    public static bool TrySetTextExcludedFromHistory(string text)
    {
        var data = new DataObject();
        data.SetData(DataFormats.UnicodeText, autoConvert: false, text);
        return TrySet(data);
    }

    [DllImport("user32.dll")]
    private static extern uint GetClipboardSequenceNumber();

    private const uint CF_UNICODETEXT = 13;

    [DllImport("user32.dll")]
    private static extern bool IsClipboardFormatAvailable(uint format);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool OpenClipboard(IntPtr hwndNewOwner);

    [DllImport("user32.dll")]
    private static extern bool CloseClipboard();

    [DllImport("user32.dll")]
    private static extern IntPtr GetClipboardData(uint format);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GlobalLock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern bool GlobalUnlock(IntPtr hMem);

    [DllImport("kernel32.dll")]
    private static extern UIntPtr GlobalSize(IntPtr hMem);
}
