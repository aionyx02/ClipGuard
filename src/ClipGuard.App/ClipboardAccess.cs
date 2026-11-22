using System.Runtime.InteropServices;

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

    public static string? TryGetText() =>
        Retry(() => Clipboard.ContainsText() ? Clipboard.GetText() : null);

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
}
