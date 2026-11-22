using System.Runtime.InteropServices;

namespace ClipGuard.App;

/// <summary>
/// 用隱藏的 message-only 視窗接收 WM_CLIPBOARDUPDATE。
/// 比輪詢省資源，也不會像舊的 SetClipboardViewer 鏈那樣被別的程式弄斷。
/// </summary>
internal sealed class ClipboardMonitor : NativeWindow, IDisposable
{
    private const int WM_CLIPBOARDUPDATE = 0x031D;
    private static readonly IntPtr HWND_MESSAGE = new(-3);

    public event EventHandler? ClipboardChanged;

    public ClipboardMonitor()
    {
        CreateHandle(new CreateParams { Parent = HWND_MESSAGE });
        if (!AddClipboardFormatListener(Handle))
            throw new InvalidOperationException($"AddClipboardFormatListener 失敗：{Marshal.GetLastWin32Error()}");
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_CLIPBOARDUPDATE)
            ClipboardChanged?.Invoke(this, EventArgs.Empty);
        base.WndProc(ref m);
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            RemoveClipboardFormatListener(Handle);
            DestroyHandle();
        }
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
}
