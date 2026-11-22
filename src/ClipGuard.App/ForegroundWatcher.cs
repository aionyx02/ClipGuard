using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace ClipGuard.App;

/// <summary>
/// 用 SetWinEventHook(EVENT_SYSTEM_FOREGROUND) 監看前景視窗切換。
/// WINEVENT_OUTOFCONTEXT 的回呼會透過建立它的執行緒的訊息迴圈送回來，所以要在 UI 執行緒建立。
/// </summary>
internal sealed class ForegroundWatcher : IDisposable
{
    private const uint EVENT_SYSTEM_FOREGROUND = 0x0003;
    private const uint WINEVENT_OUTOFCONTEXT = 0x0000;
    private const uint WINEVENT_SKIPOWNPROCESS = 0x0002;
    private const int OBJID_WINDOW = 0;

    public sealed record WindowInfo(IntPtr Handle, string ClassName, string Title, string ProcessName);

    public event Action<WindowInfo>? ForegroundChanged;

    // 委派要留著參考，否則被 GC 回收後 Windows 會呼叫到已釋放的函式指標。
    private readonly WinEventProc _proc;
    private IntPtr _hook;

    public ForegroundWatcher()
    {
        _proc = OnWinEvent;
        _hook = SetWinEventHook(EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND, IntPtr.Zero, _proc, 0, 0,
            WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS);
        if (_hook == IntPtr.Zero)
            throw new InvalidOperationException("SetWinEventHook 失敗");
    }

    private void OnWinEvent(IntPtr hook, uint evt, IntPtr hwnd, int idObject, int idChild, uint thread, uint time)
    {
        if (hwnd == IntPtr.Zero || idObject != OBJID_WINDOW) return;
        try
        {
            ForegroundChanged?.Invoke(Describe(hwnd));
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // 回呼裡的例外會讓整個程式掛掉；視窗可能剛好關掉，忽略這次即可。
        }
    }

    private static WindowInfo Describe(IntPtr hwnd)
    {
        var cls = new StringBuilder(256);
        GetClassName(hwnd, cls, cls.Capacity);
        var title = new StringBuilder(256);
        GetWindowText(hwnd, title, title.Capacity);

        var process = "";
        GetWindowThreadProcessId(hwnd, out var pid);
        if (pid != 0)
        {
            try { using var p = Process.GetProcessById((int)pid); process = p.ProcessName; }
            catch (ArgumentException) { } // 行程已結束
            catch (InvalidOperationException) { }
        }
        return new WindowInfo(hwnd, cls.ToString(), title.ToString(), process);
    }

    public void Dispose()
    {
        if (_hook != IntPtr.Zero)
        {
            UnhookWinEvent(_hook);
            _hook = IntPtr.Zero;
        }
    }

    private delegate void WinEventProc(IntPtr hWinEventHook, uint eventType, IntPtr hwnd, int idObject, int idChild,
        uint idEventThread, uint dwmsEventTime);

    [DllImport("user32.dll")]
    private static extern IntPtr SetWinEventHook(uint eventMin, uint eventMax, IntPtr hmodWinEventProc,
        WinEventProc lpfnWinEventProc, uint idProcess, uint idThread, uint dwFlags);

    [DllImport("user32.dll")]
    private static extern bool UnhookWinEvent(IntPtr hWinEventHook);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
}
