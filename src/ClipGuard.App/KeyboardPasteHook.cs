using System.Diagnostics;
using System.Runtime.InteropServices;

namespace ClipGuard.App;

/// <summary>貼上用的組合鍵。重送時照原樣送回去（有些程式的 Ctrl+Shift+V 是「貼上純文字」）。</summary>
internal enum PasteChord
{
    CtrlV,
    CtrlShiftV,
    ShiftInsert,
}

/// <summary>
/// 低階鍵盤 hook（WH_KEYBOARD_LL），只看 Ctrl+V、Ctrl+Shift+V、Shift+Insert 和 Enter。
///
/// - 回呼跑在安裝它的執行緒（UI 執行緒）的訊息迴圈裡；Windows 對回呼有逾時限制（LowLevelHooksTimeout），
///   逾時太多次會被默默拔掉，所以回呼只讀欄位、做純邏輯判斷，對話框一律用 BeginInvoke 排到之後。
/// - 回呼裡的例外會讓整個程式掛掉、也可能讓按鍵卡住，所以全部吞掉並照常交給下一個 hook。
/// - 我們自己用 SendInput 送出的按鍵帶 <see cref="InjectedMarker"/>，hook 看到就直接放行，不會再攔一次。
/// - 不記錄任何按鍵；除了上面幾個組合鍵，其他按鍵完全不看。
/// </summary>
internal sealed class KeyboardPasteHook : IDisposable
{
    /// <summary>放在 KEYBDINPUT.dwExtraInfo 的標記（"CLGP"），用來認出自己送的按鍵。</summary>
    public static readonly IntPtr InjectedMarker = new(0x434C4750);

    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN = 0x0100;
    private const int WM_SYSKEYDOWN = 0x0104;
    private const int VK_SHIFT = 0x10, VK_CONTROL = 0x11, VK_MENU = 0x12, VK_LWIN = 0x5B, VK_RWIN = 0x5C;
    private const int VK_RETURN = 0x0D, VK_INSERT = 0x2D, VK_V = 0x56;

    /// <summary>收到貼上組合鍵；回傳 true 表示吞掉這次按鍵。參數是當下的前景視窗。</summary>
    public Func<IntPtr, PasteChord, bool>? PastePressed { get; set; }

    /// <summary>收到 Enter；回傳 true 表示吞掉。用在確認框還沒搶到焦點的空檔。</summary>
    public Func<IntPtr, bool>? EnterPressed { get; set; }

    // 委派要留著參考，否則被 GC 回收後 Windows 會呼叫到已釋放的函式指標。
    private readonly HookProc _proc;
    private IntPtr _hook;

    public KeyboardPasteHook()
    {
        _proc = Callback;
    }

    public bool Installed => _hook != IntPtr.Zero;

    /// <summary>安裝 hook。失敗時回傳 Win32 錯誤碼，成功或已安裝回傳 0。</summary>
    public int Install()
    {
        if (_hook != IntPtr.Zero) return 0;
        using var module = Process.GetCurrentProcess().MainModule;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, _proc, GetModuleHandle(module?.ModuleName), 0);
        return _hook == IntPtr.Zero ? Marshal.GetLastWin32Error() : 0;
    }

    public void Uninstall()
    {
        if (_hook == IntPtr.Zero) return;
        UnhookWindowsHookEx(_hook);
        _hook = IntPtr.Zero;
    }

    public void Dispose() => Uninstall();

    private IntPtr Callback(int nCode, IntPtr wParam, IntPtr lParam)
    {
        try
        {
            if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
            {
                var k = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
                if (k.dwExtraInfo != InjectedMarker && Classify(k.vkCode) is { } key)
                {
                    var fg = GetForegroundWindow();
                    var swallow = key == Key.Enter
                        ? EnterPressed?.Invoke(fg) ?? false
                        : PastePressed?.Invoke(fg, key == Key.ShiftInsert ? PasteChord.ShiftInsert
                            : key == Key.CtrlShiftV ? PasteChord.CtrlShiftV : PasteChord.CtrlV) ?? false;
                    if (swallow) return 1;
                }
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // 判斷出錯就放行：寧可漏攔，也不能讓使用者的鍵盤失靈。
        }
        return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private enum Key { CtrlV, CtrlShiftV, ShiftInsert, Enter }

    private static Key? Classify(uint vk)
    {
        if (vk == VK_RETURN) return Key.Enter;
        if (vk != VK_V && vk != VK_INSERT) return null;

        bool Down(int v) => (GetAsyncKeyState(v) & 0x8000) != 0;
        var ctrl = Down(VK_CONTROL);
        var shift = Down(VK_SHIFT);
        // Ctrl+Alt 是 AltGr，Win+V 是剪貼簿歷程記錄：都不是一般的貼上。
        if (Down(VK_MENU) || Down(VK_LWIN) || Down(VK_RWIN)) return null;

        if (vk == VK_V && ctrl) return shift ? Key.CtrlShiftV : Key.CtrlV;
        if (vk == VK_INSERT && shift && !ctrl) return Key.ShiftInsert;
        return null;
    }

    // ---------------------------------------------------------------- 送出按鍵

    /// <summary>
    /// 對目前的前景視窗送出貼上組合鍵（帶標記，hook 會放行）。
    /// 使用者手上還按著的修飾鍵不再按一次、也不放開，避免把實體按鍵的狀態弄亂。
    /// </summary>
    public static bool SendPaste(PasteChord chord)
    {
        var inputs = new List<INPUT>();
        var mods = chord switch
        {
            PasteChord.CtrlV => new[] { VK_CONTROL },
            PasteChord.CtrlShiftV => [VK_CONTROL, VK_SHIFT],
            _ => [VK_SHIFT],
        };
        var pressed = mods.Where(m => (GetAsyncKeyState(m) & 0x8000) == 0).ToList();
        // 使用者還按著 Alt 或 Win 時送出去會變成別的組合鍵，乾脆不送。
        if ((GetAsyncKeyState(VK_MENU) & 0x8000) != 0 || (GetAsyncKeyState(VK_LWIN) & 0x8000) != 0
            || (GetAsyncKeyState(VK_RWIN) & 0x8000) != 0) return false;

        var key = chord == PasteChord.ShiftInsert ? VK_INSERT : VK_V;
        foreach (var m in pressed) inputs.Add(MakeKey(m, up: false));
        inputs.Add(MakeKey(key, up: false));
        inputs.Add(MakeKey(key, up: true));
        for (var i = pressed.Count - 1; i >= 0; i--) inputs.Add(MakeKey(pressed[i], up: true));

        var arr = inputs.ToArray();
        return SendInput((uint)arr.Length, arr, Marshal.SizeOf<INPUT>()) == arr.Length;
    }

    private static INPUT MakeKey(int vk, bool up)
    {
        const uint KEYEVENTF_EXTENDEDKEY = 0x0001, KEYEVENTF_KEYUP = 0x0002;
        var flags = up ? KEYEVENTF_KEYUP : 0;
        if (vk == VK_INSERT) flags |= KEYEVENTF_EXTENDEDKEY;   // 方向鍵區的 Insert，不是數字鍵盤的 0
        return new INPUT
        {
            type = 1, // INPUT_KEYBOARD
            u = new InputUnion
            {
                ki = new KEYBDINPUT
                {
                    wVk = (ushort)vk,
                    wScan = (ushort)MapVirtualKey((uint)vk, 0),
                    dwFlags = flags,
                    dwExtraInfo = InjectedMarker,
                },
            },
        };
    }

    // ---------------------------------------------------------------- Win32

    private delegate IntPtr HookProc(int nCode, IntPtr wParam, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT
    {
        public uint vkCode;
        public uint scanCode;
        public uint flags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct INPUT
    {
        public uint type;
        public InputUnion u;
    }

    [StructLayout(LayoutKind.Explicit)]
    private struct InputUnion
    {
        [FieldOffset(0)] public MOUSEINPUT mi;
        [FieldOffset(0)] public KEYBDINPUT ki;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MOUSEINPUT
    {
        public int dx, dy;
        public uint mouseData, dwFlags, time;
        public IntPtr dwExtraInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct KEYBDINPUT
    {
        public ushort wVk;
        public ushort wScan;
        public uint dwFlags;
        public uint time;
        public IntPtr dwExtraInfo;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern IntPtr SetWindowsHookEx(int idHook, HookProc lpfn, IntPtr hMod, uint dwThreadId);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(IntPtr hhk);

    [DllImport("user32.dll")]
    private static extern IntPtr CallNextHookEx(IntPtr hhk, int nCode, IntPtr wParam, IntPtr lParam);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr GetModuleHandle(string? lpModuleName);

    [DllImport("user32.dll")]
    private static extern short GetAsyncKeyState(int vKey);

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll", SetLastError = true)]
    private static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

    [DllImport("user32.dll")]
    private static extern uint MapVirtualKey(uint uCode, uint uMapType);
}
