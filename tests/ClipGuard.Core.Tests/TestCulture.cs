using System.Globalization;
using System.Runtime.CompilerServices;

namespace ClipGuard.Core.Tests;

/// <summary>
/// 既有測試斷言的是 zh-TW 的文字（#27 之前介面只有繁中），所以整個測試組件固定用 zh-TW 跑，
/// 不受 CI 機器（en-US）或開發者電腦語系影響。要測英文時用 <see cref="Use"/> 暫時切換。
/// </summary>
internal static class TestCulture
{
#pragma warning disable CA2255 // 測試組件用 ModuleInitializer 設定全域語系是刻意的
    [ModuleInitializer]
#pragma warning restore CA2255
    internal static void Init()
    {
        CultureInfo.DefaultThreadCurrentUICulture = UiCulture.TraditionalChinese;
        CultureInfo.CurrentUICulture = UiCulture.TraditionalChinese;
    }

    /// <summary>在 using 範圍內改用指定的介面語系（只影響目前的執行緒／非同步流程）。</summary>
    internal static IDisposable Use(string name)
    {
        var previous = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(name);
        return new Restore(previous);
    }

    private sealed class Restore(CultureInfo previous) : IDisposable
    {
        public void Dispose() => CultureInfo.CurrentUICulture = previous;
    }
}
