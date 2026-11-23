using System.Diagnostics;
using System.Text;
using System.Text.Json;
using ClipGuard.Core;
using Xunit.Abstractions;

namespace ClipGuard.Core.Tests;

/// <summary>
/// #27：通用包與國家包、上下文關鍵字、包的選擇。樣本都是假資料：官方公布的範例號碼，
/// 或是在執行時用演算法補上檢查碼的號碼（§8），沒有任何真實的人。
/// </summary>
public class SecretPacksTests(ITestOutputHelper output)
{
    private static readonly IReadOnlySet<string> All = SecretPacks.ForRegion(null, SecretPacks.Countries);

    private static IReadOnlySet<string> Packs(params string[] countries) => SecretPacks.ForRegion(null, countries);

    private static SecretMatch Single(string text, IReadOnlySet<string> packs) => Assert.Single(SecretDetector.Find(text, packs));

    private static void None(string text, IReadOnlySet<string> packs) =>
        Assert.True(SecretDetector.Find(text, packs).Count == 0,
            $"{text}: {string.Join(", ", SecretDetector.Find(text, packs).Select(m => $"{m.Label} {m.Masked}"))}");

    // ---------- 執行時補檢查碼（跟 Checksums 分開實作，順便交叉驗證） ----------

    private static string Iban(string country, string bban)
    {
        var rearranged = bban + country + "00";
        var mod = 0;
        foreach (var c in rearranged)
            mod = char.IsAsciiDigit(c) ? (mod * 10 + (c - '0')) % 97 : (mod * 100 + (c - 'A' + 10)) % 97;
        return $"{country}{98 - mod:D2}{bban}";
    }

    private static string ChinaId(string first17)
    {
        int[] w = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        var sum = first17.Select((c, i) => (c - '0') * w[i]).Sum();
        return first17 + "10X98765432"[sum % 11];
    }

    private static string MyNumber(string first11)
    {
        var sum = 0;
        for (var n = 1; n <= 11; n++) sum += (first11[11 - n] - '0') * (n <= 6 ? n + 1 : n - 5);
        var r = sum % 11;
        return first11 + (r <= 1 ? 0 : 11 - r);
    }

    private static string WithFirstValid(string prefix, string candidates, Func<string, bool> valid) =>
        candidates.Select(c => prefix + c).First(valid);

    // ---------- 通用包 ----------

    [Theory]
    [InlineData("DE89 3704 0044 0532 0130 00", "DE89********3000")]   // ECBS 公布的範例
    [InlineData("DE89370400440532013000", "DE89********3000")]
    [InlineData("GB82 WEST 1234 5698 7654 32", "GB82********5432")]    // SWIFT 公布的範例
    public void IBAN_官方範例(string iban, string masked)
    {
        var text = $"請匯款到 {iban}，謝謝";
        var m = Single(text, SecretPacks.ForRegion("en-US"));   // 通用包：不管地區都開
        Assert.Equal(SecretKind.BankAccount, m.Kind);
        Assert.Equal(masked, m.Masked);
        Assert.Equal(iban, text.Substring(m.Index, m.Length));
    }

    [Fact]
    public void IBAN_執行時產生()
    {
        foreach (var (country, bban) in new[] { ("NL", "ABNA0417164300"), ("FR", "20041010050500013M02606"), ("NO", "86011117947"), ("CH", "00762011623852957") })
        {
            var iban = Iban(country, bban);
            Assert.True(Checksums.IsValidIban(iban), iban);
            Assert.Equal(SecretKind.BankAccount, Single($"IBAN: {iban}", All).Kind);
        }
    }

    [Theory]
    [InlineData("DE88 3704 0044 0532 0130 00")]   // 檢查碼錯
    [InlineData("ZZ89 3704 0044 0532 0130 00")]   // 沒有這個國家
    [InlineData("DE89 3704 0044 0532 0130 0")]    // 長度不對
    [InlineData("de89 3704 0044 0532 0130 00")]   // 小寫不算（見已知缺口）
    [InlineData("XDE89370400440532013000")]       // 黏在更長的字串裡
    [InlineData("DE89 3704  0044 0532 0130 00")]  // 兩個空白
    public void IBAN_不該命中(string text) => None(text, All);

    [Theory]
    [InlineData("+1 202-555-0123", "+12******123")]          // 北美的 555-01xx 是保留給虛構用的號碼
    [InlineData("+1 (202) 555-0123", "+12******123")]
    [InlineData("+44 20 7946 0958", "+44*******958")]       // Ofcom 保留給戲劇用的號碼
    [InlineData("+61 491 570 156", "+61******156")]         // ACMA 保留給虛構用的號碼
    [InlineData("+81 3-0000-0000", "+81******000")]
    [InlineData("+852 0000 0000", "+85******000")]
    public void 國際電話(string phone, string masked)
    {
        var text = $"Call me at {phone}.";
        var m = Single(text, SecretPacks.ForRegion("en-US"));
        Assert.Equal(SecretKind.PhoneNumber, m.Kind);
        Assert.Equal(masked, m.Masked);
        Assert.Equal(phone, text.Substring(m.Index, m.Length));
    }

    [Theory]
    [InlineData("202-555-0123")]          // 沒有 +：保守起見不算
    [InlineData("(202) 555-0123")]
    [InlineData("+1 123 456 7890")]       // 北美區碼不能是 1 開頭
    [InlineData("+1 202 555 01234")]      // 北美要剛好 11 碼
    [InlineData("+999 1234 5678")]        // 沒分配的國碼
    [InlineData("+0800")]                 // 時區
    [InlineData("UTC+08:00 2024-01-15")]
    [InlineData("+12")]
    [InlineData("x+12025550123")]         // 黏在英數字後面（例如程式碼）
    [InlineData("+1202555012345678")]     // 超過 15 碼
    [InlineData("得分 +5 1234")]
    [InlineData("version 1.0.0+20240115")]
    public void 國際電話_不該命中(string text) => None(text, All);

    [Fact]
    public void 台灣手機優先於國際電話()
    {
        var m = Single("+886 912-345-678", SecretPacks.Default);
        Assert.Equal(SecretKind.MobilePhone, m.Kind);
        Assert.Equal("091****678", m.Masked);
        // 沒開台灣包時，一樣用國際電話提醒。
        Assert.Equal(SecretKind.PhoneNumber, Single("+886 912-345-678", SecretPacks.ForRegion("en-US")).Kind);
    }

    // ---------- 中國 ----------

    [Fact]
    public void 中國居民身分證()
    {
        const string sample = "11010519491231002X";   // GB 11643-1999 標準裡的範例
        Assert.True(Checksums.IsValidChinaResidentId(sample));
        var m = Single($"身份证号：{sample}", Packs("CN"));
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("110********02X", m.Masked);

        var generated = ChinaId("44030420000101123");
        Assert.Equal(SecretKind.NationalId, Single($"{generated} 張三", Packs("CN")).Kind);
        Assert.Equal(SecretKind.NationalId, Single("110105 19491231 002x", Packs("CN")).Kind);   // 小寫 x、空白分段
    }

    [Theory]
    [InlineData("110105194912310021")]    // 檢查碼錯
    [InlineData("911105194912310021")]    // 地區碼不能是 9 開頭
    [InlineData("1110105194912310021")]   // 黏在更長的數字裡
    public void 中國居民身分證_不該命中(string text) => None(text, All);

    [Fact]
    public void 中國居民身分證_日期要是真的()
    {
        var feb30 = ChinaId("11010519490230002");
        Assert.False(Checksums.IsValidChinaResidentId(feb30));
        None(feb30, All);
        // 只開台灣包時不偵測。
        None("11010519491231002X", SecretPacks.Default);
    }

    // ---------- 日本 ----------

    [Fact]
    public void 個人番號要有關鍵字()
    {
        Assert.True(Checksums.IsValidMyNumber("123456789018"));   // 常見的說明用範例
        var jp = Packs("JP");
        var m = Single("マイナンバー：1234 5678 9018", jp);
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("********9018", m.Masked);
        Assert.Single(SecretDetector.Find("個人番号 1234-5678-9018", jp));
        Assert.Single(SecretDetector.Find($"My Number: {MyNumber("98765432109")}", jp));
        None("追跡番号 1234 5678 9018", jp);                      // 12 位數太常見：沒有關鍵字不算
        None("123456789018", jp);
        None("マイナンバー：1234 5678 9017", jp);                  // 檢查碼錯
    }

    // ---------- 韓國 ----------

    [Fact]
    public void 住民登錄番號要有關鍵字()
    {
        var kr = Packs("KR");
        var m = Single("주민등록번호: 900101-1234567", kr);
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("********567", m.Masked);
        Assert.Single(SecretDetector.Find("RRN 9001011234567", kr));
        None("900101-1234567", kr);                 // 沒有關鍵字
        None("주민등록번호: 901301-1234567", kr);    // 沒有 13 月
        None("주민등록번호: 900101-9234567", kr);    // 第 7 碼只到 8
    }

    // ---------- 香港 ----------

    [Fact]
    public void 香港身分證()
    {
        var hk = Packs("HK");
        Assert.True(Checksums.IsValidHongKongId("A1234563"));   // 常見的說明用範例 A123456(3)
        var m = Single("身份證 A123456(3)", hk);
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("A*****63", m.Masked);
        Assert.Single(SecretDetector.Find("A123456(3)", hk));           // 有括號：不需要關鍵字
        Assert.Single(SecretDetector.Find("HKID: A1234563", hk));      // 沒括號：要有關鍵字
        var twoLetters = WithFirstValid("XA987654", "0123456789A", Checksums.IsValidHongKongId);
        Assert.Single(SecretDetector.Find($"HKID {twoLetters}", hk));
        var checkA = WithFirstValid("", Enumerable.Range(100000, 900).Select(n => $"B{n}A").ToArray(), Checksums.IsValidHongKongId);
        Assert.Single(SecretDetector.Find($"{checkA[..^1]}(A)", hk));   // 檢查碼是 A
        None("A1234563", hk);               // 沒括號又沒關鍵字：像產品型號
        None("A123456(4)", hk);             // 檢查碼錯
        None("XA123456(3)A", hk);
    }

    private static string WithFirstValid(string prefix, string[] candidates, Func<string, bool> valid) =>
        candidates.Select(c => prefix + c).First(valid);

    // ---------- 新加坡 ----------

    [Theory]
    [InlineData("S1234567D", SecretKind.NationalId)]     // 常見的說明用範例
    [InlineData("T1234567J", SecretKind.NationalId)]
    [InlineData("F1234567N", SecretKind.ResidentCertificate)]
    [InlineData("G1234567X", SecretKind.ResidentCertificate)]
    [InlineData("M1234567K", SecretKind.ResidentCertificate)]
    public void 新加坡_NRIC_FIN(string id, SecretKind kind)
    {
        var m = Single($"NRIC/FIN: {id}", Packs("SG"));
        Assert.Equal(kind, m.Kind);
        Assert.Equal($"{id[0]}******{id[^2..]}", m.Masked);
    }

    [Theory]
    [InlineData("S1234567A")]   // 檢查字母錯
    [InlineData("A1234567D")]   // 沒有 A 開頭的
    [InlineData("S1234567DX")]
    [InlineData("s1234567d")]
    public void 新加坡_不該命中(string text) => None(text, Packs("SG"));

    // ---------- 美國 ----------

    [Theory]
    [InlineData("SSN: 078-05-1120")]                 // SSA 已作廢的範例號碼（Woolworth 錢包卡）
    [InlineData("Social Security Number 219 09 9999")]   // SSA 宣傳品上的範例號碼
    [InlineData("ssn=078051120")]
    [InlineData("078-05-1120 (SSN)")]                // 關鍵字在後面
    [InlineData("Social Security\n078-05-1120")]     // 表單上換行
    public void SSN要有關鍵字(string text)
    {
        var m = Single(text, SecretPacks.ForRegion("en-US"));
        Assert.Equal(SecretKind.NationalId, m.Kind);
        var digits = PiiFormats.Digits(text.Substring(m.Index, m.Length));
        Assert.Equal(9, digits.Length);
        Assert.Equal("*****" + digits[^4..], m.Masked);
    }

    [Theory]
    [InlineData("078-05-1120")]                // 沒有關鍵字
    [InlineData("Order 078-05-1120")]
    [InlineData("SSN: 000-12-3456")]           // 區碼 000
    [InlineData("SSN: 666-12-3456")]
    [InlineData("SSN: 900-12-3456")]           // 9xx 不會發（ITIN 用）
    [InlineData("SSN: 123-00-4567")]           // 組號 00
    [InlineData("SSN: 123-45-0000")]           // 序號 0000
    [InlineData("SSN: 123-45 6789")]           // 分隔符號不一致
    [InlineData("Bar Assn. 078-05-1120")]      // ssn 在單字裡
    [InlineData("SSN is required.\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nCall 078-05-1120")] // 太遠
    public void SSN_不該命中(string text) => None(text, SecretPacks.ForRegion("en-US"));

    [Fact]
    public void 上下文_全形與大小寫()
    {
        var us = SecretPacks.ForRegion("en-US");
        Assert.Single(SecretDetector.Find("ＳＳＮ：０７８－０５－１１２０", us));
        Assert.Single(SecretDetector.Find("sSn 078-05-1120", us));
    }

    [Fact]
    public void 統編_關鍵字在單字裡不算()
    {
        // 「vat」不能比到 private、derivative（以前的 regex 會）。
        None("private 12345675", SecretPacks.Default);
        Assert.Single(SecretDetector.Find("VAT 12345675", SecretPacks.Default));
        Assert.Single(SecretDetector.Find("統一編號\n12345675", SecretPacks.Default));   // 表格裡換行
    }

    // ---------- 包的選擇 ----------

    [Theory]
    [InlineData("TW", "TW")]
    [InlineData("zh-TW", "TW")]
    [InlineData("zh-Hant-TW", "TW")]
    [InlineData("en-US", "US")]
    [InlineData("US", "US")]
    [InlineData("ja-JP", "JP")]
    [InlineData("ja", "JP")]
    [InlineData("ko", "KR")]
    [InlineData("zh_CN", "CN")]
    [InlineData("zh-Hant-HK", "HK")]
    [InlineData("en-SG", "SG")]
    [InlineData("en", null)]
    [InlineData("fr-FR", null)]
    [InlineData("zh", null)]
    [InlineData("", null)]
    [InlineData(null, null)]
    public void 地區對應國家包(string? region, string? pack) => Assert.Equal(pack, SecretPacks.CountryOf(region));

    [Fact]
    public void 包的選擇()
    {
        Assert.Equal(["CN", "HK", "JP", "KR", "SG", "TW", "US"], SecretPacks.Countries);
        Assert.Equal(new HashSet<string> { "universal", "US" }, SecretPacks.ForRegion("en-US"));
        Assert.Equal(new HashSet<string> { "universal", "US", "JP" }, SecretPacks.ForRegion("en-US", ["jp", "XX"]));
        Assert.Equal(new HashSet<string> { "universal" }, SecretPacks.ForRegion("zh-TW", disabled: ["TW"]));
        Assert.Equal(new HashSet<string> { "universal", "TW" }, SecretPacks.Default);
    }

    [Fact]
    public void 地區是美國時不偵測台灣身分證()
    {
        var us = SecretPacks.ForRegion("en-US");
        Assert.Empty(SecretDetector.Find("身分證 A123456789", us));
        Assert.Equal(SecretKind.CreditCard, Single("4111 1111 1111 1111", us).Kind);   // 通用包照常
        Assert.Equal(SecretKind.NationalId, Single("身分證 A123456789", SecretPacks.ForRegion("zh-TW")).Kind);
    }

    [Fact]
    public void 包設定檔()
    {
        var dir = Path.Combine(Path.GetTempPath(), "clipguard-packs-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new SecretPackSettingsStore(dir);
            Assert.Same(SecretPackSettings.Default, store.Load(out var error));
            Assert.Null(error);

            store.Save(new SecretPackSettings { Extra = ["jp", " US ", "jp"], Disabled = ["TW"] });
            var loaded = store.Load(out error);
            Assert.Null(error);
            Assert.Equal(["JP", "US"], loaded.Extra);
            Assert.Equal(["TW"], loaded.Disabled);
            Assert.Contains("\"extra\"", File.ReadAllText(Path.Combine(dir, SecretPackSettingsStore.FileName)));

            File.WriteAllText(Path.Combine(dir, SecretPackSettingsStore.FileName), "{ not json");
            Assert.Same(SecretPackSettings.Default, store.Load(out error));
            Assert.NotNull(error);
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    // ---------- 規則檔格式 ----------

    [Theory]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","regex":"a","finder":"card-groups"}]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x"}]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","finder":"nope"}]}""")]
    [InlineData("""{"format":1,"priority":1,"pack":"tw","rules":[]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","regex":"a","context":{"keywords":["SSN"],"before":5}}]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","regex":"a","context":{"keywords":["ssn"],"before":40}}]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","regex":"a","context":{"keywords":["ssn"]}}]}""")]
    [InlineData("""{"format":1,"priority":1,"rules":[{"id":"x","kind":"national-id","label":"x","regex":"a","mask":{"canonical":"nope"}}]}""")]
    public void 規則檔的新欄位格式錯誤會報錯(string json) =>
        Assert.Throws<InvalidDataException>(() => SecretRules.Load([("bad.json", json)]));

    // ---------- 誤報 ----------

    public static TheoryData<string> PiiFalsePositives() =>
    [
        "2024-01-15 2024-02-16 2024-03-17 2024-04-18",
        "會議日期：2023/11/22、2023/11/23、2023.11.24",
        "20240115123045 20240115123046",                       // 時間戳記
        "訂單 20240115-0001 20240115-0002 20240115-0003",
        "Order #1234 5678 9012, tracking 1Z999AA10123456784",
        "追跡番号 1234-5678-9018",                              // 12 位數，沒有マイナンバー
        "電話 202-555-0123、02-2555-6666、(02)25556666",
        "123e4567-e89b-12d3-a456-426614174000",
        "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
        "DE89A1B2C3D4E5F6A7B8C9D0",                             // 大寫 hex，DE 開頭
        "SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==",
        "版本 1.2.3.4，下一版 4.1.11.1111，semver 1.0.0+20240115",
        "192.168.100.200 10.0.0.1 172.16.254.1 +1.5%",
        "Part no. S1234567A, SKU A1234563, model AB123456(7)", // 檢查碼不對的型號
        "價格 +5 1234、溫度 +12.5、時區 UTC+0800",
        "身分證 A123456788（檢查碼錯）",
        "110105194912310021 是一個 18 位數",
        "ISBN 978-0-306-40615-7 ISSN 0317-8471",
        "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678 commit",
    ];

    [Theory]
    [MemberData(nameof(PiiFalsePositives))]
    public void 所有包都開時的誤報樣本(string text) => None(text, All);

    [Fact]
    public void 共用誤報樣本在所有包都開時也不該命中()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "fixtures", "secret-false-positives.json");
        using var doc = JsonDocument.Parse(File.ReadAllText(path));
        foreach (var s in doc.RootElement.GetProperty("samples").EnumerateArray())
        {
            var found = SecretDetector.Find(s.GetProperty("text").GetString(), All);
            Assert.True(found.Count == 0, $"{s.GetProperty("name").GetString()}: {string.Join(", ", found.Select(m => $"{m.Label} {m.Masked}"))}");
        }
    }

    // ---------- 效能 ----------

    private static string Fill(string unit, int length)
    {
        var sb = new StringBuilder(length + unit.Length);
        while (sb.Length < length) sb.Append(unit);
        return sb.ToString(0, length);
    }

    public static IEnumerable<(string Name, string Text)> PathologicalPii(int n) =>
    [
        ("數字", Fill("1", n)),
        ("單碼數字組", Fill("1 ", n)),
        ("+1 ", Fill("+1 ", n)),
        ("+ 加 15 碼", Fill("+123456789012345 ", n)),
        ("字母數字", Fill("A1", n)),
        ("IBAN 前綴", Fill("DE89 ", n)),
        ("大寫英數", Fill("DE8937040044", n)),
        ("括號", Fill("A123456(", n)),
        ("SSN 關鍵字", Fill("SSN 078-05-1120 ", n)),
        ("マイナンバー", Fill("マイナンバー 1234 5678 9018 ", n)),
        ("주민등록번호", Fill("주민등록번호 900101-1234567 ", n)),
        ("統編", Fill("統編 12345675 ", n)),
        ("關鍵字沒有號碼", Fill("ssn マイナンバー 주민번호 hkid 統編 ", n)),
        ("身分證", Fill("A123456789 ", n)),
    ];

    [Fact]
    public void 個資規則在_1Mi_病態輸入上都是線性時間()
    {
        const int n = 1 << 20;
        var inputs = PathologicalPii(n).ToList();
        var worst = (Ms: 0L, Id: "", Input: "");
        foreach (var rule in SecretRules.All.Where(r => r.Kind != SecretKind.ApiKey))
        {
            foreach (var (name, text) in inputs)
            {
                var ascii = SecretRules.AsciiView(text);
                var sw = Stopwatch.StartNew();
                _ = rule.Scan(ascii, text).Count();
                sw.Stop();
                if (sw.ElapsedMilliseconds > worst.Ms) worst = (sw.ElapsedMilliseconds, rule.Id, name);
            }
        }
        output.WriteLine($"個資規則最慢 {worst.Ms} ms（{worst.Id}，{worst.Input}）");
        // 門檻抓的是「平方時間」（1 Mi 字會到分鐘級），不是絕對速度：CI 機器比本機慢 4 倍以上。
        Assert.True(worst.Ms < 2000, $"{worst.Id} took {worst.Ms} ms");
    }

    [Fact]
    public void 所有包都開時_1Mi_不會卡住()
    {
        SecretDetector.Find("warm up A123456789", All);
        long worst = 0;
        foreach (var (name, text) in PathologicalPii(SecretDetector.MaxScanLength))
        {
            var sw = Stopwatch.StartNew();
            var found = SecretDetector.Find(text, All);
            sw.Stop();
            worst = Math.Max(worst, sw.ElapsedMilliseconds);
            output.WriteLine($"{name}: {text.Length:N0} 字，{found.Count:N0} 筆，{sw.ElapsedMilliseconds} ms");
            Assert.True(sw.ElapsedMilliseconds < 3000, $"{name} took {sw.ElapsedMilliseconds} ms");
        }
        output.WriteLine($"最慢 {worst} ms");
    }
}
