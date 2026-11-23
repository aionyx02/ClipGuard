using System.Globalization;

namespace ClipGuard.Core;

/// <summary>
/// 介面語系（#27）：目前只有英文（中性語系，<c>en</c>）和繁體中文（<c>zh-TW</c>）。
/// 只決定 <see cref="CultureInfo.CurrentUICulture"/>（要用哪一份文字）；日期、數字格式仍跟著 Windows 地區設定。
/// </summary>
/// <remarks>
/// 對應規則：
/// <list type="bullet">
/// <item>繁體中文（zh-TW、zh-HK、zh-MO、zh-Hant…）→ zh-TW。</item>
/// <item>簡體中文（zh-CN、zh-SG、zh-Hans）和單獨的 zh → 英文。簡中使用者看繁中不一定比英文順，
///   而且 Chrome 插件在 zh_CN 也會退回英文（沒有 zh_CN 翻譯），兩邊一致。之後有簡中翻譯再加。</item>
/// <item>其他語系 → 英文。</item>
/// </list>
/// 測試或想看另一種語言時可以強制指定：命令列 <c>--lang=en</c>（或 <c>--lang en</c>）優先，
/// 其次是環境變數 <c>CLIPGUARD_LANG</c>。值不認得時忽略，照 Windows 的顯示語言。
/// </remarks>
public static class UiCulture
{
    public const string EnvironmentVariable = "CLIPGUARD_LANG";

    public static CultureInfo English { get; } = CultureInfo.GetCultureInfo("en");
    public static CultureInfo TraditionalChinese { get; } = CultureInfo.GetCultureInfo("zh-TW");

    /// <summary>把任意語系對應到有翻譯的語系。</summary>
    public static CultureInfo Map(CultureInfo culture)
    {
        for (var c = culture; !c.Equals(CultureInfo.InvariantCulture); c = c.Parent)
        {
            // zh-TW、zh-HK、zh-MO 的上一層都是 zh-Hant；舊名稱 zh-CHT 也算。
            if (c.Name is "zh-TW" or "zh-Hant" or "zh-CHT") return TraditionalChinese;
        }
        return English;
    }

    /// <summary>
    /// 決定介面語系：命令列 &gt; 環境變數 &gt; 系統的顯示語言。
    /// </summary>
    public static CultureInfo Resolve(IReadOnlyList<string> args, string? environmentValue, CultureInfo system)
    {
        var forced = Parse(FromArgs(args)) ?? Parse(environmentValue);
        return Map(forced ?? system);
    }

    /// <summary>依 <see cref="Resolve"/> 設定這個行程的介面語系（含之後建立的執行緒）。</summary>
    public static CultureInfo Apply(IReadOnlyList<string> args)
    {
        var culture = Resolve(args, Environment.GetEnvironmentVariable(EnvironmentVariable), CultureInfo.CurrentUICulture);
        CultureInfo.DefaultThreadCurrentUICulture = culture;
        CultureInfo.CurrentUICulture = culture;
        return culture;
    }

    private static string? FromArgs(IReadOnlyList<string> args)
    {
        for (var i = 0; i < args.Count; i++)
        {
            var a = args[i];
            if (a.StartsWith("--lang=", StringComparison.OrdinalIgnoreCase)) return a["--lang=".Length..];
            if (a.Equals("--lang", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Count) return args[i + 1];
        }
        return null;
    }

    private static CultureInfo? Parse(string? name)
    {
        name = name?.Trim().Replace('_', '-');
        if (string.IsNullOrEmpty(name)) return null;
        try
        {
            // PredefinedOnly：打錯字（例如 "zz-QQ"）會丟例外而不是造出一個假的語系。
            return CultureInfo.GetCultureInfo(name, predefinedOnly: true);
        }
        catch (CultureNotFoundException)
        {
            return null;
        }
    }
}
