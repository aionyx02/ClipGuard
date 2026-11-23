using System.Reflection;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ClipGuard.Core;

/// <summary>
/// 共用規則檔（repo 根目錄的 <c>rules/*.json</c>，#26）。桌面版以內嵌資源載入（不讀檔、不連網，P3），
/// 插件用 <c>tools/build-extension-rules.mjs</c> 產生的 <c>extension/lib/rules.generated.js</c>。
/// 格式與語法限制見 docs/detection-rules.md §5.4。
/// </summary>
internal static class SecretRules
{
    private const string ResourcePrefix = "ClipGuard.Rules.";

    // 規則的 regex 一律用 NonBacktracking：最壞情況也是線性時間（RE2 語法本來就沒有 lookaround 和 backreference）。
    // ExplicitCapture：NonBacktracking 只用來找範圍，群組另外取（見 CompileGroups），不必付捕獲的成本。
    private const RegexOptions Opts = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant | RegexOptions.ExplicitCapture;

    private static readonly Lazy<IReadOnlyList<SecretRule>> Loaded = new(() => Load(ReadEmbedded()));

    /// <summary>所有規則，依檔案的 priority、再依檔案內的順序排列。前面的規則在重疊時優先。</summary>
    public static IReadOnlyList<SecretRule> All => Loaded.Value;

    /// <summary>內嵌的規則檔（檔名, 內容），依檔名排序。</summary>
    internal static IEnumerable<(string Name, string Json)> ReadEmbedded()
    {
        var asm = typeof(SecretRules).Assembly;
        foreach (var name in asm.GetManifestResourceNames().Where(n => n.StartsWith(ResourcePrefix, StringComparison.Ordinal)).Order(StringComparer.Ordinal))
        {
            using var stream = asm.GetManifestResourceStream(name)!;
            using var reader = new StreamReader(stream, Encoding.UTF8);
            yield return (name[ResourcePrefix.Length..], reader.ReadToEnd());
        }
    }

    internal static IReadOnlyList<SecretRule> Load(IEnumerable<(string Name, string Json)> files)
    {
        var parsed = new List<(int Priority, string Name, List<SecretRule> Rules)>();
        var cache = new Dictionary<(string, bool), Regex>();
        var ids = new HashSet<string>(StringComparer.Ordinal);

        foreach (var (name, json) in files)
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.GetProperty("format").GetInt32() != 1) throw new InvalidDataException($"{name}: 不支援的 format");
            var priority = root.GetProperty("priority").GetInt32();
            var fileExclude = ReadExclusions(root, cache, name);
            var fileStopwords = ReadStrings(root, "stopwords");

            var rules = new List<SecretRule>();
            foreach (var r in root.GetProperty("rules").EnumerateArray())
            {
                var id = r.GetProperty("id").GetString()!;
                if (!ids.Add(id)) throw new InvalidDataException($"{name}: 規則 id 重複：{id}");
                try
                {
                    rules.Add(ReadRule(r, id, fileExclude, fileStopwords, cache, name));
                }
                catch (Exception e) when (e is ArgumentException or KeyNotFoundException or InvalidOperationException or NotSupportedException)
                {
                    throw new InvalidDataException($"{name}: 規則 {id} 無效：{e.Message}", e);
                }
            }
            parsed.Add((priority, name, rules));
        }

        return [.. parsed.OrderBy(p => p.Priority).ThenBy(p => p.Name, StringComparer.Ordinal).SelectMany(p => p.Rules)];
    }

    private static SecretRule ReadRule(JsonElement r, string id, Exclusion[] fileExclude, string[] fileStopwords,
        Dictionary<(string, bool), Regex> cache, string file)
    {
        var ignoreCase = r.TryGetProperty("ignoreCase", out var ic) && ic.GetBoolean();
        var keepStart = 0;
        var pem = false;
        if (r.TryGetProperty("mask", out var mask))
        {
            if (mask.ValueKind == JsonValueKind.String)
            {
                if (mask.GetString() != "pem-block") throw new InvalidDataException($"{file}: {id} 的 mask 不認得");
                pem = true;
            }
            else keepStart = mask.TryGetProperty("keepStart", out var ks) ? ks.GetInt32() : 0;
        }

        return new SecretRule
        {
            Id = id,
            Kind = r.GetProperty("kind").GetString() switch
            {
                "api-key" => SecretKind.ApiKey,
                var k => throw new InvalidDataException($"{file}: {id} 的 kind 不認得：{k}"),
            },
            Label = r.GetProperty("label").GetString()!,
            Pattern = Compile(r.GetProperty("regex").GetString()!, ignoreCase, cache),
            GroupPattern = CompileGroups(r.GetProperty("regex").GetString()!, ignoreCase),
            SecretGroup = r.TryGetProperty("secretGroup", out var sg) ? sg.GetInt32() : null,
            Keywords = ReadStrings(r, "keywords"),
            NotPrecededBy = r.TryGetProperty("notPrecededBy", out var np) ? Compile($"^(?:{np.GetString()})$", false, cache) : null,
            NotFollowedBy = r.TryGetProperty("notFollowedBy", out var nf) ? Compile($"^(?:{nf.GetString()})", false, cache) : null,
            MinLength = r.TryGetProperty("minLength", out var min) ? min.GetInt32() : 1,
            MaxLength = r.TryGetProperty("maxLength", out var max) ? max.GetInt32() : int.MaxValue,
            Entropy = r.TryGetProperty("entropy", out var en) ? EntropyThreshold.Read(en) : null,
            DigitRequiredBelow = r.TryGetProperty("digitRequiredBelow", out var dr) ? (int)Math.Min(int.MaxValue, dr.GetDouble()) : 0,
            RejectSequential = r.TryGetProperty("rejectSequential", out var rs) && rs.GetBoolean(),
            Exclusions = [.. ReadExclusions(r, cache, file), .. fileExclude],
            Stopwords = [.. ReadStrings(r, "stopwords"), .. fileStopwords],
            Validate = r.TryGetProperty("validate", out var v) ? v.GetString() switch
            {
                "jwt-header" => SecretValidators.IsJwt,
                var n => throw new InvalidDataException($"{file}: {id} 的 validate 不認得：{n}"),
            } : null,
            KeepStart = keepStart,
            PemBlock = pem,
        };
    }

    private static Exclusion[] ReadExclusions(JsonElement e, Dictionary<(string, bool), Regex> cache, string file)
    {
        if (!e.TryGetProperty("exclude", out var arr)) return [];
        return [.. arr.EnumerateArray().Select(x => new Exclusion(
            Compile(x.GetProperty("regex").GetString()!, false, cache),
            x.TryGetProperty("ignoreCase", out var ic) && ic.GetBoolean(),
            x.TryGetProperty("target", out var t) ? t.GetString() switch
            {
                "secret" => ExclusionTarget.Secret,
                "match" => ExclusionTarget.Match,
                "line" => ExclusionTarget.Line,
                "key" => ExclusionTarget.Key,
                var n => throw new InvalidDataException($"{file}: exclude 的 target 不認得：{n}"),
            } : ExclusionTarget.Secret))];
    }

    private static string[] ReadStrings(JsonElement e, string name) =>
        e.TryGetProperty(name, out var arr) ? [.. arr.EnumerateArray().Select(x => x.GetString()!)] : [];

    private static Regex Compile(string pattern, bool ignoreCase, Dictionary<(string, bool), Regex> cache)
    {
        if (cache.TryGetValue((pattern, ignoreCase), out var r)) return r;
        r = new Regex(ToDotNet(pattern), ignoreCase ? Opts | RegexOptions.IgnoreCase : Opts);
        cache[(pattern, ignoreCase)] = r;
        return r;
    }

    /// <summary>
    /// 取群組用的 regex（一般的回溯引擎，只套在 NonBacktracking 找到的那一段上）。
    /// .NET 9 的 NonBacktracking 找到的範圍是對的，但某些 pattern 的捕獲群組會是空的（例如 context-assignment），
    /// 所以範圍交給 NonBacktracking（線性時間），群組在那一小段裡用 ^(?:…)\z 重新比一次。沒有群組的規則不需要。
    /// </summary>
    private static Regex? CompileGroups(string pattern, bool ignoreCase)
    {
        var dotnet = ToDotNet(pattern);
        var probe = new Regex(dotnet, RegexOptions.CultureInvariant);
        if (probe.GetGroupNumbers().Length <= 1) return null;
        var opts = RegexOptions.CultureInvariant | (ignoreCase ? RegexOptions.IgnoreCase : 0);
        return new Regex($@"^(?:{dotnet})\z", opts, TimeSpan.FromMilliseconds(200));
    }

    /// <summary>
    /// 規則檔的 <c>$</c> 是「整段文字的結尾」（跟 JS 沒有 m 旗標時一樣）；.NET 的 <c>$</c> 在最後一個換行前面也成立，
    /// 所以換成 <c>\z</c>。字元類別裡的 <c>$</c> 和跳脫過的 <c>\$</c> 不動。
    /// </summary>
    internal static string ToDotNet(string pattern)
    {
        var sb = new StringBuilder(pattern.Length + 8);
        var inClass = false;
        for (var i = 0; i < pattern.Length; i++)
        {
            var c = pattern[i];
            if (c == '\\' && i + 1 < pattern.Length)
            {
                sb.Append(c).Append(pattern[++i]);
                continue;
            }
            if (inClass)
            {
                if (c == ']') inClass = false;
                sb.Append(c);
                continue;
            }
            if (c == '[')
            {
                inClass = true;
                sb.Append(c);
                // 緊接在 [ 或 [^ 後面的 ] 是字面字元。
                if (i + 1 < pattern.Length && pattern[i + 1] == '^') sb.Append(pattern[++i]);
                if (i + 1 < pattern.Length && pattern[i + 1] == ']') sb.Append(pattern[++i]);
                continue;
            }
            if (c == '$') sb.Append(@"\z");
            else sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// 比對用的 ASCII 版本：非 ASCII 字元換成 U+001A，長度不變（位置可以直接對回正規化後的文字）。
    /// 規則的 \b、\w、IgnoreCase 在 .NET 會認 Unicode，在 JS 只認 ASCII；只給它們 ASCII 就兩邊一樣（§5.4）。
    /// </summary>
    internal static string AsciiView(string text)
    {
        var i = 0;
        while (i < text.Length && text[i] < 0x80) i++;
        if (i == text.Length) return text;
        return string.Create(text.Length, text, static (span, t) =>
        {
            for (var k = 0; k < t.Length; k++) span[k] = t[k] < 0x80 ? t[k] : '\u001a';
        });
    }
}

internal enum ExclusionTarget { Secret, Match, Line, Key }

internal sealed record Exclusion(Regex Pattern, bool IgnoreCase, ExclusionTarget Target);

/// <summary>亂度門檻：固定值（gitleaks），或依字元組成分類、隨長度調整的 min(cap, a + b·log2(長度))。</summary>
internal sealed class EntropyThreshold
{
    private double _fixed = double.NaN;
    private (double A, double B, double Cap) _hex, _base36, _base64;

    public static EntropyThreshold Read(JsonElement e)
    {
        var t = new EntropyThreshold();
        if (e.ValueKind == JsonValueKind.Number)
        {
            t._fixed = e.GetDouble();
            return t;
        }
        static (double, double, double) Abc(JsonElement x) => (x[0].GetDouble(), x[1].GetDouble(), x[2].GetDouble());
        t._hex = Abc(e.GetProperty("hex"));
        t._base36 = Abc(e.GetProperty("base36"));
        t._base64 = Abc(e.GetProperty("base64"));
        return t;
    }

    public double For(string secret)
    {
        if (!double.IsNaN(_fixed)) return _fixed;
        var (a, b, cap) = SecretValidators.Charset(secret) switch
        {
            Charset.Hex => _hex,
            Charset.Base36 => _base36,
            _ => _base64,
        };
        return Math.Min(cap, a + b * Math.Log2(secret.Length));
    }
}

internal enum Charset { Hex, Base36, Base64 }

internal static class SecretValidators
{
    /// <summary>Shannon entropy（每個字元幾 bit），跟 gitleaks 的算法相同。</summary>
    public static double Entropy(string s)
    {
        if (s.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var c in s) counts[c] = counts.GetValueOrDefault(c) + 1;
        double h = 0;
        foreach (var n in counts.Values)
        {
            var p = (double)n / s.Length;
            h -= p * Math.Log2(p);
        }
        return h;
    }

    public static Charset Charset(string s)
    {
        // UUID 這種「hex 加連字號」也算 hex（亂度上限一樣是 4 bit）。
        if (s.All(c => char.IsAsciiHexDigit(c) || c == '-')) return Core.Charset.Hex;
        if (s.All(c => char.IsAsciiDigit(c) || char.IsAsciiLetterLower(c)) || s.All(c => char.IsAsciiDigit(c) || char.IsAsciiLetterUpper(c)))
            return Core.Charset.Base36;
        return Core.Charset.Base64;
    }

    /// <summary>一半以上的相鄰字元是相同或連號（aaaa、0123456789abcdef、abcdefgh），不像隨機產生的 key。</summary>
    public static bool IsSequential(string s)
    {
        if (s.Length < 2) return true;
        var close = 0;
        for (var i = 1; i < s.Length; i++)
            if (Math.Abs(s[i] - s[i - 1]) <= 1) close++;
        return close * 2 >= s.Length - 1;
    }

    /// <summary>JWT：header（第一個句點之前）要能解成 JSON 物件，而且有字串型別的 <c>alg</c>。</summary>
    public static bool IsJwt(string token)
    {
        var dot = token.IndexOf('.');
        var segment = dot < 0 ? token : token[..dot];
        var b64 = segment.Replace('-', '+').Replace('_', '/');
        b64 += (b64.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        var buffer = new byte[b64.Length];
        if (b64.Length % 4 == 1 || !Convert.TryFromBase64String(b64, buffer, out var written)) return false;
        try
        {
            using var doc = JsonDocument.Parse(buffer.AsMemory(0, written));
            return doc.RootElement.ValueKind == JsonValueKind.Object
                   && doc.RootElement.TryGetProperty("alg", out var alg)
                   && alg.ValueKind == JsonValueKind.String;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

/// <summary>規則檔裡的一條規則（已編譯）。</summary>
internal sealed class SecretRule
{
    public required string Id { get; init; }
    public required SecretKind Kind { get; init; }
    public required string Label { get; init; }
    /// <summary>通知裡顯示的名稱：CoreStrings 有 <c>RuleLabel_&lt;id&gt;</c> 就用它（有翻譯），否則用規則檔的 label。</summary>
    public string DisplayLabel => CoreStrings.Lookup("RuleLabel_" + Id) ?? Label;
    public required Regex Pattern { get; init; }
    /// <summary>有捕獲群組時，在比對到的範圍裡重新取群組用（見 <c>SecretRules.CompileGroups</c>）。</summary>
    public Regex? GroupPattern { get; init; }
    /// <summary>機密是哪個捕獲群組；null 表示第一個有比對到、而且不是空字串的群組，沒有群組就是整段（同 gitleaks）。</summary>
    public int? SecretGroup { get; init; }
    /// <summary>小寫；文字（轉小寫後）裡至少要出現一個才跑 regex。空的表示一律跑。</summary>
    public required string[] Keywords { get; init; }
    public Regex? NotPrecededBy { get; init; }
    public Regex? NotFollowedBy { get; init; }
    public int MinLength { get; init; } = 1;
    public int MaxLength { get; init; } = int.MaxValue;
    public EntropyThreshold? Entropy { get; init; }
    public int DigitRequiredBelow { get; init; }
    public bool RejectSequential { get; init; }
    public required Exclusion[] Exclusions { get; init; }
    public required string[] Stopwords { get; init; }
    public Func<string, bool>? Validate { get; init; }
    /// <summary>遮罩時保留的前綴長度（例如 <c>ghp_</c>）。</summary>
    public int KeepStart { get; init; }
    /// <summary>PEM 標頭：通知原樣顯示標頭，貼遮罩版時從標頭遮到 END 行（見 PasteGuard）。</summary>
    public bool PemBlock { get; init; }

    public bool KeywordsPresent(string lower)
    {
        if (Keywords.Length == 0) return true;
        foreach (var k in Keywords)
            if (lower.Contains(k, StringComparison.Ordinal)) return true;
        return false;
    }

    /// <summary>
    /// 在 <paramref name="ascii"/>（<see cref="SecretRules.AsciiView"/>）裡找這條規則的機密。
    /// 回傳機密的位置；字串本身從 <paramref name="text"/>（同長度的正規化文字）取，給遮罩用。
    /// </summary>
    public IEnumerable<(int Index, int Length, string Secret)> Scan(string ascii, string text)
    {
        foreach (Match span in Pattern.Matches(ascii))
        {
            if (NotPrecededBy is not null && span.Index > 0 && NotPrecededBy.IsMatch(ascii.AsSpan(span.Index - 1, 1))) continue;
            var end = span.Index + span.Length;
            if (NotFollowedBy is not null && end < ascii.Length
                && NotFollowedBy.Match(ascii, end, Math.Min(64, ascii.Length - end)).Success) continue;

            var m = span;
            if (GroupPattern is not null)
            {
                try
                {
                    m = GroupPattern.Match(ascii, span.Index, span.Length);
                }
                catch (RegexMatchTimeoutException)
                {
                    continue;
                }
                if (!m.Success) continue;
            }
            var g = SecretGroupOf(m);
            if (g.Length < MinLength || g.Length > MaxLength) continue;
            var secret = text.Substring(g.Index, g.Length);
            if (!Accept(secret, m, g, ascii)) continue;
            yield return (g.Index, g.Length, secret);
        }
    }

    private Group SecretGroupOf(Match m)
    {
        if (SecretGroup is { } n) return m.Groups[n];
        for (var k = 1; k < m.Groups.Count; k++)
            if (m.Groups[k].Success && m.Groups[k].Length > 0) return m.Groups[k];
        return m;
    }

    private bool Accept(string secret, Match m, Group g, string ascii)
    {
        if (Entropy is not null && SecretValidators.Entropy(secret) <= Entropy.For(secret)) return false;
        if (DigitRequiredBelow > 0 && secret.Length < DigitRequiredBelow && !secret.Any(char.IsAsciiDigit)) return false;
        if (RejectSequential && SecretValidators.IsSequential(secret)) return false;
        if (Stopwords.Length > 0)
        {
            var lower = secret.ToLowerInvariant();
            foreach (var w in Stopwords)
                if (lower.Contains(w, StringComparison.Ordinal)) return false;
        }
        foreach (var e in Exclusions)
        {
            var target = e.Target switch
            {
                ExclusionTarget.Match => m.Value,
                ExclusionTarget.Line => LineOf(ascii, m.Index, m.Index + m.Length),
                ExclusionTarget.Key => KeyOf(ascii, m),
                _ => secret,
            };
            if (e.IgnoreCase) target = target.ToLowerInvariant();
            if (e.Pattern.IsMatch(target)) return false;
        }
        return Validate is null || Validate(secret);
    }

    private static string LineOf(string s, int start, int end)
    {
        var a = start > 0 ? s.LastIndexOf('\n', start - 1) + 1 : 0;
        var b = s.IndexOf('\n', end);
        return s[a..(b < 0 ? s.Length : b)];
    }

    /// <summary>金鑰名稱：群組 1 往前延伸到整個識別字（最多 40 字），例如 <c>MY_SECRET</c> 而不只是 <c>SECRET</c>。</summary>
    internal static string KeyOf(string s, Match m)
    {
        var g = m.Groups.Count > 1 ? m.Groups[1] : (Group)m;
        var start = g.Index;
        var limit = Math.Max(0, start - 40);
        while (start > limit && IsKeyChar(s[start - 1])) start--;
        return s.Substring(start, g.Index + g.Length - start);
    }

    private static bool IsKeyChar(char c) => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-';
}
