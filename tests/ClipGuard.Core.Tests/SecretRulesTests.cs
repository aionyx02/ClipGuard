using System.Diagnostics;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ClipGuard.Core;
using Xunit.Abstractions;

namespace ClipGuard.Core.Tests;

/// <summary>
/// 共用規則檔（rules/*.json，#26）：載入、三層偵測、誤報樣本、效能。
/// 像 key 的樣本一律在執行時用固定種子的亂數產生，不把完整的 key 寫進檔案（§8）。
/// </summary>
public class SecretRulesTests(ITestOutputHelper output)
{
    // ---------- 測試資料產生（與 extension/test/rules.test.js 的 gen 相同） ----------

    private const string Alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Hex = "0123456789abcdef";
    private const string Lower = "abcdefghijklmnopqrstuvwxyz0123456789";

    /// <summary>固定種子的 LCG，C# 和 JS 產生一樣的字串。</summary>
    private sealed class Gen(uint seed)
    {
        private uint _state = seed;
        public string Next(string charset, int length)
        {
            var sb = new StringBuilder(length);
            for (var i = 0; i < length; i++)
            {
                _state = (_state * 1103515245 + 12345) & 0x7fffffff;
                sb.Append(charset[(int)(_state >> 8) % charset.Length]);
            }
            return sb.ToString();
        }
    }

    private static IReadOnlyList<SecretMatch> ApiKeys(string text) =>
        [.. SecretDetector.Find(text).Where(m => m.Kind == SecretKind.ApiKey)];

    // ---------- 載入 ----------

    [Fact]
    public void 規則檔都載得進來而且_id_不重複()
    {
        var rules = SecretRules.All;
        output.WriteLine($"{rules.Count} 條規則");
        Assert.True(rules.Count > 200);
        Assert.Equal(rules.Count, rules.Select(r => r.Id).Distinct().Count());
        Assert.Equal("jwt", rules[0].Id);                     // api-keys.json（priority 10）排最前面
        Assert.StartsWith("context-", rules[^1].Id);           // context.json（priority 30）排最後
        Assert.All(rules, r => Assert.True((r.Pattern.Options & RegexOptions.NonBacktracking) != 0, r.Id));
        Assert.All(rules, r => Assert.All(r.Keywords, k => Assert.Equal(k.ToLowerInvariant(), k)));
    }

    [Fact]
    public void 規則檔格式錯誤會報出檔名和規則()
    {
        var bad = """{"format":1,"priority":1,"rules":[{"id":"x","kind":"api-key","label":"x","regex":"(?<=a)b"}]}""";
        var e = Assert.Throws<InvalidDataException>(() => SecretRules.Load([("bad.json", bad)]));
        Assert.Contains("bad.json", e.Message);
        var kind = """{"format":1,"priority":1,"rules":[{"id":"x","kind":"phone","label":"x","regex":"a"}]}""";
        Assert.Throws<InvalidDataException>(() => SecretRules.Load([("k.json", kind)]));
    }

    [Theory]
    [InlineData("a$", @"a\z")]
    [InlineData(@"a\$", @"a\$")]
    [InlineData("[$]", "[$]")]
    [InlineData("[]$]$", @"[]$]\z")]
    [InlineData("(?:x|$)", @"(?:x|\z)")]
    public void 錢字號換成字串結尾(string pattern, string expected) => Assert.Equal(expected, SecretRules.ToDotNet(pattern));

    [Fact]
    public void 錢字號在最後一個換行前面不成立()
    {
        // 規則檔的 $ 跟 JS 一樣只在整段結尾成立；.NET 原本的 $ 在結尾換行前面也成立。
        var rules = SecretRules.Load([("t.json", """{"format":1,"priority":1,"rules":[{"id":"t","kind":"api-key","label":"t","regex":"ab$"}]}""")]);
        Assert.Empty(rules[0].Scan("ab\n", "ab\n"));
        Assert.Single(rules[0].Scan("ab", "ab"));
    }

    [Fact]
    public void ASCII版本長度不變()
    {
        var text = "金鑰ghp_x😀y";
        var ascii = SecretRules.AsciiView(text);
        Assert.Equal(text.Length, ascii.Length);
        Assert.Equal("\u001a\u001aghp_x\u001a\u001ay", ascii);
    }

    [Fact]
    public void 規則檔本身沒有長得像_key_的字串()
    {
        // gitleaks 的 allowlist 有完整的範例 key（推上 GitHub 會被 push protection 擋），轉換時要拿掉。
        // 規則本身的 regex 不看：有些規則就是一段固定前綴（例如 bedrock-api-key-…），會比對到自己。
        foreach (var (name, json) in SecretRules.ReadEmbedded())
        {
            var text = Regex.Replace(json, @"""regex"": ""(?:[^""\\]|\\.)*""", @"""regex"": """"");
            var found = SecretDetector.Find(text);
            Assert.True(found.Count == 0, $"{name}: {string.Join(", ", found.Select(m => m.Label))}");
        }
    }

    // ---------- 第 1 層：已知格式 ----------

    public static TheoryData<string, string> GitleaksSamples()
    {
        var g = new Gen(26);
        return new()
        {
            { "shpat_" + g.Next(Hex, 32), "Shopify access token" },
            { "dop_v1_" + g.Next(Hex, 64), "DigitalOcean PAT" },
            { "lin_api_" + g.Next(Alnum, 40), "Linear API key" },
            { "pplx-" + g.Next(Alnum, 48), "Perplexity API key" },
            { "PMAK-" + g.Next(Hex, 24) + "-" + g.Next(Hex, 34), "Postman API token" },
            { "SK" + g.Next(Hex, 32), "Twilio API key" },
            { "ADAFRUIT_IO_KEY=" + g.Next(Lower, 32), "Adafruit API key" },
        };
    }

    [Theory]
    [MemberData(nameof(GitleaksSamples))]
    public void gitleaks規則(string sample, string label)
    {
        var m = Assert.Single(ApiKeys($"config:\n  {sample}\n"));
        Assert.Equal(label, m.Label);
        Assert.Contains('*', m.Masked);
        var secret = sample[(sample.IndexOf('=') + 1)..];
        Assert.DoesNotContain(secret, m.Masked);
    }

    [Fact]
    public void 手寫規則排在_gitleaks_前面()
    {
        // Anthropic 的 key 兩邊都抓得到，標籤以 api-keys.json 為準。
        var key = "sk-ant-api03-" + new Gen(3).Next(Alnum, 93) + "AA";
        Assert.Equal("Anthropic API key", Assert.Single(ApiKeys(key)).Label);
    }

    [Fact]
    public void 中文緊貼著_key_也找得到()
    {
        // \b 在 .NET 認得中文字是「字」；比對 ASCII 版本才會跟 JS（只認 ASCII）一樣。
        var key = "dop_v1_" + new Gen(7).Next(Hex, 64);
        Assert.Equal("DigitalOcean PAT", Assert.Single(ApiKeys($"金鑰{key} 請保管")).Label);
    }

    // ---------- 第 2 層：上下文＋亂度 ----------

    public static TheoryData<string, string> ContextSamples()
    {
        var g = new Gen(2026);
        string R(int n) => g.Next(Alnum, n);
        return new()
        {
            { $"# .env\nAPI_KEY={R(32)}\nDEBUG=false\n", "疑似金鑰或密碼" },
            { $"DB_PASSWORD=\"{R(20)}\"\n", "疑似金鑰或密碼" },
            { $"curl -H \"Authorization: Bearer {R(40)}\" https://api.example.invalid/v1/items", "Authorization 權杖" },
            { $"curl -H 'X-API-Key: {R(32)}' https://api.example.invalid/", "疑似金鑰或密碼" },
            { $"{{\"name\": \"demo\", \"apiKey\": \"{R(32)}\"}}", "疑似金鑰或密碼" },
            { $"secret_key: {g.Next(Hex, 40)}\n", "疑似金鑰或密碼" },
            { $"api_key = \"{g.Next(Lower, 32)}\"", "疑似金鑰或密碼" },
            { $"$env:SERVICE_TOKEN = \"{R(24)}\"", "疑似金鑰或密碼" },
            { $"client_secret={R(16)}&grant_type=client_credentials", "疑似金鑰或密碼" },
        };
    }

    [Theory]
    [MemberData(nameof(ContextSamples))]
    public void 上下文加亂度(string text, string label)
    {
        var m = Assert.Single(ApiKeys(text));
        Assert.Equal(label, m.Label);
        var secret = text.Substring(m.Index, m.Length);
        Assert.True(secret.Length >= 16);
        Assert.StartsWith("********", m.Masked);
        Assert.DoesNotContain(secret, m.Masked);
        // 貼遮罩版：原文整段換掉。
        Assert.DoesNotContain(secret, PasteGuard.MaskText(text, SecretDetector.Find(text)));
    }

    [Fact]
    public void 有明確的金鑰名稱時_UUID_和_SHA_也算()
    {
        // 決定（§5.5）：Heroku 等服務的 key 就是 UUID；secret=／token= 後面的 40 位 hex 多半就是 token。
        Assert.Single(ApiKeys("token: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b"));
        Assert.Single(ApiKeys("secret=3f2a9c1e7b4d6a8f0e2c5b9d1a3e7f6c4b8d2a0e"));
        // 沒有金鑰名稱，或名稱是 id、commit、hash：不算。
        Assert.Empty(ApiKeys("id: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b"));
        Assert.Empty(ApiKeys("token_id: 9f1b6c2e-4d3a-4b8e-a1f0-7c2d5e6f8a9b"));
        Assert.Empty(ApiKeys("commit: 3f2a9c1e7b4d6a8f0e2c5b9d1a3e7f6c4b8d2a0e"));
    }

    [Theory]
    [InlineData("secret=Ab1Ab1Ab1Ab1Ab1Ab1")]        // 亂度太低
    [InlineData("token=accessTokenFromStorage")]     // 沒有數字的識別字
    [InlineData("password=short1")]                  // 太短
    [InlineData("api_key=1234567890123456789")]      // 全是數字
    [InlineData("token = GetToken()")]
    [InlineData("password = input()")]
    public void 上下文加亂度_不算(string text) => Assert.Empty(ApiKeys(text));

    // ---------- 誤報樣本（與插件共用） ----------

    public static TheoryData<string> FalsePositives()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "secret-false-positives.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        var data = new TheoryData<string>();
        foreach (var s in doc.RootElement.GetProperty("samples").EnumerateArray()) data.Add(s.GetProperty("name").GetString()!);
        return data;
    }

    private static string FixtureText(string name)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "secret-false-positives.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        return doc.RootElement.GetProperty("samples").EnumerateArray()
            .First(s => s.GetProperty("name").GetString() == name).GetProperty("text").GetString()!;
    }

    [Theory]
    [MemberData(nameof(FalsePositives))]
    public void 誤報樣本(string name)
    {
        var found = ApiKeys(FixtureText(name));
        Assert.True(found.Count == 0, $"{name}: {string.Join(", ", found.Select(m => $"{m.Label} {m.Masked}"))}");
    }

    // ---------- 效能 ----------

    private static string Fill(string unit, int length)
    {
        var sb = new StringBuilder(length + unit.Length);
        while (sb.Length < length) sb.Append(unit);
        return sb.ToString(0, length);
    }

    [Fact]
    public void 每條規則在_1Mi_病態輸入上都是線性時間()
    {
        const int n = 1 << 20;
        var worst = (Ms: 0L, Id: "", Input: -1);
        long total = 0;
        foreach (var rule in SecretRules.All)
        {
            var kw = rule.Keywords.Length > 0 ? rule.Keywords[0] : "key";
            var inputs = new[]
            {
                Fill(kw + " ", n), Fill(kw + "=", n), Fill(kw + " = \"", n), Fill(kw + new string('a', 40) + " ", n),
                kw + new string('a', n - kw.Length),
            };
            for (var i = 0; i < inputs.Length; i++)
            {
                var sw = Stopwatch.StartNew();
                _ = rule.Scan(inputs[i], inputs[i]).Count();
                sw.Stop();
                total += sw.ElapsedMilliseconds;
                if (sw.ElapsedMilliseconds > worst.Ms) worst = (sw.ElapsedMilliseconds, rule.Id, i);
            }
        }
        output.WriteLine($"{SecretRules.All.Count} 條規則 × 5 種輸入：合計 {total} ms，最慢 {worst.Ms} ms（{worst.Id}，輸入 {worst.Input}）");
        Assert.True(worst.Ms < 300, $"{worst.Id} took {worst.Ms} ms");
    }

    [Fact]
    public void 所有關鍵字都出現時_1Mi_也在一秒內()
    {
        // 最壞情況：每一段都含有所有規則的 keywords，每條規則都要跑。
        var unit = string.Join(" = \"", SecretRules.All.SelectMany(r => r.Keywords).Distinct()) + " = \"" + new Gen(9).Next(Alnum, 40) + "\"\n";
        var cases = new (string Name, string Text)[]
        {
            ("所有關鍵字", Fill(unit, SecretDetector.MaxScanLength)),
            ("滿滿的 .env", Fill($"API_TOKEN={new Gen(1).Next(Alnum, 32)}\n", SecretDetector.MaxScanLength)),
            ("滿滿的 Authorization", Fill("Authorization: Bearer ", SecretDetector.MaxScanLength)),
            ("minified 單行", Fill("var token=e.token,secret=t.secret||\"\",apiKey=null;", SecretDetector.MaxScanLength)),
        };
        SecretDetector.Find("warm up api_key=x");
        foreach (var (name, text) in cases)
        {
            var sw = Stopwatch.StartNew();
            var found = SecretDetector.Find(text);
            sw.Stop();
            output.WriteLine($"{name}: {text.Length:N0} 字，{found.Count:N0} 筆，{sw.ElapsedMilliseconds} ms");
            Assert.True(sw.ElapsedMilliseconds < 1000, $"{name} took {sw.ElapsedMilliseconds} ms");
        }
    }
}
