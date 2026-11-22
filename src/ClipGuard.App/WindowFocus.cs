using System.Runtime.InteropServices;
using System.Text;
using ClipGuard.Core;

namespace ClipGuard.App;

/// <summary>前景視窗的查詢與切換。查詢會在鍵盤 hook 裡呼叫，所以只用快速的 Win32 API。</summary>
internal static class WindowFocus
{
    private static readonly uint OwnPid = (uint)Environment.ProcessId;

    // hook 每次按 Ctrl+V 都要查行程名稱；同一個行程連續貼上很常見，記住上一次的結果。
    private static uint _cachedPid;
    private static string _cachedName = "";

    public static bool IsOwnWindow(IntPtr hwnd)
    {
        if (hwnd == IntPtr.Zero) return false;
        GetWindowThreadProcessId(hwnd, out var pid);
        return pid == OwnPid;
    }

    public static PasteTarget Describe(IntPtr hwnd)
    {
        var cls = new StringBuilder(256);
        if (hwnd != IntPtr.Zero) GetClassName(hwnd, cls, cls.Capacity);
        GetWindowThreadProcessId(hwnd, out var pid);
        return new PasteTarget(ProcessName(pid), cls.ToString(), IsOwnProcess: pid != 0 && pid == OwnPid);
    }

    private static string ProcessName(uint pid)
    {
        if (pid == 0) return "";
        if (pid == _cachedPid) return _cachedName;

        var name = "";
        const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        var h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                var size = sb.Capacity;
                if (QueryFullProcessImageName(h, 0, sb, ref size)) name = PasteGuard.NormalizeAppName(sb.ToString());
            }
            finally { CloseHandle(h); }
        }
        _cachedPid = pid;
        _cachedName = name;
        return name;
    }

    /// <summary>
    /// 把視窗叫到前景並等它真的變成前景。Windows 只讓「剛收到使用者輸入」的行程切換前景，
    /// 我們的輸入被 hook 吞掉了，所以先暫時把輸入佇列接到目前前景視窗的執行緒上再切換。
    /// </summary>
    public static async Task<bool> ActivateAsync(IntPtr hwnd, int timeoutMs = 600)
    {
        if (hwnd == IntPtr.Zero || !IsWindow(hwnd)) return false;
        if (GetForegroundWindow() == hwnd) return true;

        ForceForeground(hwnd);
        for (var waited = 0; waited < timeoutMs; waited += 20)
        {
            if (GetForegroundWindow() == hwnd) return true;
            await Task.Delay(20);
        }
        return GetForegroundWindow() == hwnd;
    }

    public static void ForceForeground(IntPtr hwnd)
    {
        var fg = GetForegroundWindow();
        var fgThread = fg == IntPtr.Zero ? 0 : GetWindowThreadProcessId(fg, out _);
        var me = GetCurrentThreadId();
        var attached = fgThread != 0 && fgThread != me && AttachThreadInput(me, fgThread, true);
        try
        {
            if (IsIconic(hwnd)) ShowWindow(hwnd, 9 /* SW_RESTORE */);
            BringWindowToTop(hwnd);
            SetForegroundWindow(hwnd);
        }
        finally
        {
            if (attached) AttachThreadInput(me, fgThread, false);
        }
    }

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern bool SetForegroundWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool BringWindowToTop(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("user32.dll")]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool IsWindow(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);

    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassName(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, uint flags, StringBuilder name, ref int size);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);
}
