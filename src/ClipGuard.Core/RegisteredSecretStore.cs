using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace ClipGuard.Core;

/// <summary>
/// 保護 HMAC 金鑰的方式。正式程式用 DPAPI（<see cref="DpapiKeyProtector"/>），測試可換成假的實作。
/// </summary>
public interface IKeyProtector
{
    byte[] Protect(byte[] plaintext);
    /// <exception cref="CryptographicException">資料損毀或不是這個使用者保護的。</exception>
    byte[] Unprotect(byte[] protectedData);
}

/// <summary>一筆登記的機密。只存標籤、長度與 HMAC，不存原文，也無法還原原文。</summary>
public sealed record RegisteredSecret(Guid Id, string Label, int Length, byte[] Hmac, DateTimeOffset CreatedAt);

/// <summary>
/// 使用者登記的機密字串，用 HMAC-SHA256 比對。
///
/// 為什麼不用單純 SHA-256：身分證、手機、短密碼的可能組合只有約 1e8–1e9 種，
/// 拿到雜湊檔的人在一般電腦上幾分鐘就能全部算一遍反推出原文。
/// HMAC 的金鑰是隨機 256 位元、用 DPAPI 綁在目前 Windows 使用者上，
/// 只偷走 secrets.json 而沒有金鑰就無從暴力反推。
///
/// 檔案：
///   key.bin       DPAPI 保護過的 32 位元組隨機金鑰
///   secrets.json  [{ id, label, length, hmac(base64), createdAt }]
/// </summary>
public sealed class RegisteredSecretStore
{
    public const int MinLength = 6;
    public const int MaxLength = 256;
    // 標籤會出現在通知裡，限制長度避免把通知擠爆。
    public const int MaxLabelLength = 40;
    // 比對時最多掃這麼長；滑動視窗 × 已登記長度種類數，太長會拖慢 UI。
    public const int MaxScanLength = 20_000;

    private const string KeyFile = "key.bin";
    private const string EntriesFile = "secrets.json";
    private const int KeySize = 32;

    private static readonly JsonSerializerOptions Json = new() { WriteIndented = true };

    private readonly string _directory;
    private readonly byte[] _key;
    private readonly List<RegisteredSecret> _entries;

    public RegisteredSecretStore(string directory, IKeyProtector protector)
    {
        _directory = directory;
        Directory.CreateDirectory(directory);

        var keyPath = Path.Combine(directory, KeyFile);
        var entriesPath = Path.Combine(directory, EntriesFile);

        if (File.Exists(keyPath))
        {
            _key = protector.Unprotect(File.ReadAllBytes(keyPath));
            _entries = Load(entriesPath);
        }
        else
        {
            // 沒有金鑰時舊的 HMAC 都對不上了，留著只會讓人以為還有保護，所以一起清掉。
            _key = RandomNumberGenerator.GetBytes(KeySize);
            File.WriteAllBytes(keyPath, protector.Protect(_key));
            _entries = [];
            Save();
        }
    }

    /// <summary>
    /// 預設位置 %LOCALAPPDATA%\ClipGuard。
    /// </summary>
    public static string DefaultDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "ClipGuard");

    public IReadOnlyList<RegisteredSecret> Entries => _entries;

    public RegisteredSecret Add(string label, string secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length is < MinLength or > MaxLength)
            throw new ArgumentException($"長度必須介於 {MinLength} 到 {MaxLength} 個字元。", nameof(secret));

        var hmac = Compute(secret.AsSpan());
        if (_entries.Any(e => e.Length == secret.Length && CryptographicOperations.FixedTimeEquals(e.Hmac, hmac)))
            throw new InvalidOperationException("這個機密已經登記過了。");

        label = string.IsNullOrWhiteSpace(label) ? "未命名" : label.Trim();
        if (label.Length > MaxLabelLength) label = label[..MaxLabelLength];
        var entry = new RegisteredSecret(Guid.NewGuid(), label,
            secret.Length, hmac, DateTimeOffset.UtcNow);
        _entries.Add(entry);
        Save();
        return entry;
    }

    public bool Remove(Guid id)
    {
        var removed = _entries.RemoveAll(e => e.Id == id) > 0;
        if (removed) Save();
        return removed;
    }

    /// <summary>
    /// 對每個已登記的長度 L，取文字裡所有長度 L 的子字串算 HMAC，
    /// 以固定時間比較（FixedTimeEquals）找出符合的登記項目。每個項目最多回報一次。
    /// 結果只帶標籤，不帶任何原文字元：登記的多半是密碼，連頭尾幾碼都不該出現在通知裡。
    /// </summary>
    public IReadOnlyList<SecretMatch> Find(string? text)
    {
        if (string.IsNullOrEmpty(text) || _entries.Count == 0) return [];
        if (text.Length > MaxScanLength) text = text[..MaxScanLength];

        var results = new List<SecretMatch>();
        Span<byte> mac = stackalloc byte[HMACSHA256.HashSizeInBytes];
        using var hmac = new HMACSHA256(_key);

        foreach (var group in _entries.GroupBy(e => e.Length))
        {
            var length = group.Key;
            var candidates = group.ToList();
            for (var i = 0; i + length <= text.Length && candidates.Count > 0; i++)
            {
                Hash(hmac, text.AsSpan(i, length), mac);
                for (var j = candidates.Count - 1; j >= 0; j--)
                {
                    var e = candidates[j];
                    if (!CryptographicOperations.FixedTimeEquals(e.Hmac, mac)) continue;
                    results.Add(new(SecretKind.Registered, e.Label, $"已登記的「{e.Label}」", i, length));
                    candidates.RemoveAt(j);
                }
            }
        }
        results.Sort((a, b) => a.Index.CompareTo(b.Index));
        return results;
    }

    private byte[] Compute(ReadOnlySpan<char> value)
    {
        using var hmac = new HMACSHA256(_key);
        var mac = new byte[HMACSHA256.HashSizeInBytes];
        Hash(hmac, value, mac);
        return mac;
    }

    private static void Hash(HMACSHA256 hmac, ReadOnlySpan<char> value, Span<byte> destination)
    {
        // 機密最長 256 字元；UTF-16 每個 char 轉 UTF-8 最多 3 bytes（代理對是 2 char → 4 bytes），stackalloc 足夠。
        Span<byte> utf8 = stackalloc byte[MaxLength * 3];
        var n = Encoding.UTF8.GetBytes(value, utf8);
        hmac.TryComputeHash(utf8[..n], destination, out _);
        CryptographicOperations.ZeroMemory(utf8[..n]);
    }

    private static List<RegisteredSecret> Load(string path)
    {
        if (!File.Exists(path)) return [];
        return JsonSerializer.Deserialize<List<RegisteredSecret>>(File.ReadAllText(path), Json) ?? [];
    }

    private void Save()
    {
        // 先寫暫存檔再取代，避免寫到一半當機留下壞掉的檔案。
        var path = Path.Combine(_directory, EntriesFile);
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(_entries, Json));
        File.Move(tmp, path, overwrite: true);
    }
}
