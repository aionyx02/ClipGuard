using System.Text.Json;

namespace ClipGuard.Core;

/// <summary>
/// 個資規則包（#27）：通用包一律開啟；國家包依地區設定自動選，使用者可以手動加或關。
/// 包的名稱就是規則檔的 <c>pack</c>（<c>universal</c> 或 ISO 3166 的兩碼國家代碼）。
/// 與 extension/lib/rules.js 的 packsForLocales 用同一套對應。
/// </summary>
public static class SecretPacks
{
    public const string Universal = "universal";

    /// <summary>沒有指定時用的包：通用包＋台灣包（#27 之前的行為）。桌面版啟動時會改用 <see cref="ForRegion"/> 的結果。</summary>
    public static IReadOnlySet<string> Default { get; } = new HashSet<string>(StringComparer.Ordinal) { Universal, "TW" };

    /// <summary>規則檔裡所有的國家包，依代碼排序。</summary>
    public static IReadOnlyList<string> Countries { get; } =
        [.. SecretRules.All.Select(r => r.Pack).Where(p => p != Universal).Distinct().Order(StringComparer.Ordinal)];

    // 只有語言、沒有地區的寫法（瀏覽器常見的 ja、ko）：語言幾乎只在一個國家用的才對應。
    private static readonly Dictionary<string, string> LanguageOnly = new(StringComparer.Ordinal) { ["ja"] = "JP", ["ko"] = "KR" };

    /// <summary>
    /// 地區設定（<c>TW</c>、<c>RegionInfo.CurrentRegion.TwoLetterISORegionName</c>）或語系名稱（<c>zh-TW</c>、<c>en-US</c>、
    /// <c>zh-Hant-HK</c>、<c>ja</c>）對應的國家包；沒有對應的包時回傳 null。
    /// </summary>
    public static string? CountryOf(string? regionOrCulture)
    {
        if (string.IsNullOrWhiteSpace(regionOrCulture)) return null;
        var parts = regionOrCulture.Trim().Split('-', '_');
        string? region = null;
        if (parts.Length == 1)
        {
            var p = parts[0];
            // 單獨兩個大寫字母是地區（RegionInfo），小寫是語言（navigator.language = "ja"）。
            if (p.Length == 2 && p.All(char.IsAsciiLetterUpper)) region = p;
            else if (LanguageOnly.TryGetValue(p.ToLowerInvariant(), out var r)) region = r;
        }
        else
        {
            region = parts.Skip(1).FirstOrDefault(p => p.Length == 2 && p.All(char.IsAsciiLetter))?.ToUpperInvariant();
            if (region is null && LanguageOnly.TryGetValue(parts[0].ToLowerInvariant(), out var r)) region = r;
        }
        return region is not null && Countries.Contains(region) ? region : null;
    }

    /// <summary>
    /// 要開的包：通用包、地區對應的國家包、<paramref name="extra"/>（手動加的），再拿掉 <paramref name="disabled"/>（手動關的）。
    /// 不認得的國家代碼直接忽略。
    /// </summary>
    public static IReadOnlySet<string> ForRegion(string? regionOrCulture, IEnumerable<string>? extra = null, IEnumerable<string>? disabled = null)
    {
        var set = new HashSet<string>(StringComparer.Ordinal) { Universal };
        if (CountryOf(regionOrCulture) is { } country) set.Add(country);
        foreach (var e in extra ?? [])
            if (Known(e) is { } k) set.Add(k);
        foreach (var d in disabled ?? [])
            if (Known(d) is { } k) set.Remove(k);
        return set;
    }

    private static string? Known(string? pack)
    {
        var p = pack?.Trim().ToUpperInvariant();
        return p is not null && Countries.Contains(p) ? p : null;
    }
}

/// <summary>手動加或關的國家包（<see cref="SecretPacks.ForRegion"/> 的 extra／disabled）。</summary>
public sealed record SecretPackSettings
{
    public static SecretPackSettings Default { get; } = new();
    public IReadOnlyList<string> Extra { get; init; } = [];
    public IReadOnlyList<string> Disabled { get; init; } = [];
}

/// <summary>
/// 規則包設定的存取：<c>%LOCALAPPDATA%\ClipGuard\secret-packs.json</c>，例如 <c>{"extra": ["JP"], "disabled": []}</c>。
/// 目前沒有設定畫面，要手動編輯；檔案不存在就用預設值（只依地區設定），不含任何機密。
/// </summary>
public sealed class SecretPackSettingsStore
{
    public const string FileName = "secret-packs.json";
    private const int MaxEntries = 32;

    private static readonly JsonSerializerOptions Json = new()
    {
        WriteIndented = true, PropertyNameCaseInsensitive = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly string _path;

    public SecretPackSettingsStore(string directory)
    {
        _path = Path.Combine(directory, FileName);
    }

    /// <summary>讀取設定。檔案不存在或損毀時回傳預設值（損毀時 <paramref name="error"/> 會有原因）。</summary>
    public SecretPackSettings Load(out string? error)
    {
        error = null;
        if (!File.Exists(_path)) return SecretPackSettings.Default;
        try
        {
            var dto = JsonSerializer.Deserialize<Dto>(File.ReadAllText(_path), Json);
            return dto is null ? SecretPackSettings.Default : new SecretPackSettings { Extra = Clean(dto.Extra), Disabled = Clean(dto.Disabled) };
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            error = ex.Message;
            return SecretPackSettings.Default;
        }
    }

    public void Save(SecretPackSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(new Dto([.. Clean(settings.Extra)], [.. Clean(settings.Disabled)]), Json));
        File.Move(tmp, _path, overwrite: true);
    }

    private static List<string> Clean(IEnumerable<string>? packs) =>
        [.. (packs ?? []).Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim().ToUpperInvariant())
            .Where(p => p.Length == 2).Distinct(StringComparer.Ordinal).Take(MaxEntries)];

    private sealed record Dto(List<string>? Extra = null, List<string>? Disabled = null);
}
