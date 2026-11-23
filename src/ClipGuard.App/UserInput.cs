using System.Runtime.InteropServices;

namespace ClipGuard.App;

/// <summary>使用者閒置多久（GetLastInputInfo）。只取時間，不裝 hook、不記錄任何按鍵。</summary>
internal static class UserInput
{
    public static TimeSpan? IdleTime()
    {
        var info = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref info)) return null;
        // 兩者都是開機後的毫秒數（32 位元，約 49.7 天繞回），用無號減法處理繞回。
        return TimeSpan.FromMilliseconds(unchecked((uint)Environment.TickCount - info.dwTime));
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
}
