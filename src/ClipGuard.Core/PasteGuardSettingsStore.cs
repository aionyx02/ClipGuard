using System.Text.Json;

namespace ClipGuard.Core;

/// <summary>
/// 貼上攔截設定的存取：<c>%LOCALAPPDATA%\ClipGuard\paste-guard.json</c>。
/// 檔案只有開關與程式名稱，不含任何機密或剪貼簿內容。檔案不存在就用預設值，沒改過設定不會建立檔案。
/// </summary>
public sealed class PasteGuardSettingsStore
{
    public const string FileName = "paste-guard.json";
    // 允許清單是給人手動加的，設上限避免壞掉的檔案拖慢每次貼上的比對。
    public const int MaxAllowedApps = 100;
    public const int MaxAppNameLength = 100;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly string _path;

    public PasteGuardSettingsStore(string directory)
    {
        _path = Path.Combine(directory, FileName);
    }

    /// <summary>讀取設定。檔案不存在或損毀時回傳預設值（損毀時 <paramref name="error"/> 會有原因）。</summary>
    public PasteGuardSettings Load(out string? error)
    {
        error = null;
        if (!File.Exists(_path)) return PasteGuardSettings.Default;
        try
        {
            var dto = JsonSerializer.Deserialize<Dto>(File.ReadAllText(_path), Json);
            return dto is null ? PasteGuardSettings.Default : Sanitize(dto);
        }
        catch (Exception ex) when (ex is JsonException or IOException or UnauthorizedAccessException)
        {
            error = ex.Message;
            return PasteGuardSettings.Default;
        }
    }

    public void Save(PasteGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
        var clean = Sanitize(new Dto(settings.InterceptRegistered, settings.InterceptDetected, settings.AllowedApps.ToList()));
        var tmp = _path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(
            new Dto(clean.InterceptRegistered, clean.InterceptDetected, clean.AllowedApps.ToList()), Json));
        File.Move(tmp, _path, overwrite: true);
    }

    private static PasteGuardSettings Sanitize(Dto dto) => new()
    {
        InterceptRegistered = dto.InterceptRegistered,
        InterceptDetected = dto.InterceptDetected,
        AllowedApps = (dto.AllowedApps ?? [])
            .Select(PasteGuard.NormalizeAppName)
            .Where(a => a.Length is > 0 and <= MaxAppNameLength)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(MaxAllowedApps)
            .ToList(),
    };

    private sealed record Dto(bool InterceptRegistered = true, bool InterceptDetected = false, List<string>? AllowedApps = null);
}
