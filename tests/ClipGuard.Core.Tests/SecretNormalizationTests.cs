using System.Diagnostics;
using System.Text;
using ClipGuard.Core;
using Xunit.Abstractions;

namespace ClipGuard.Core.Tests;

/// <summary>#22：全形、分隔符號、零寬字元、超長文字、JWT。樣本全是假資料（自己算的檢查碼、公開測試卡號）。</summary>
public class SecretNormalizationTests(ITestOutputHelper output)
{
    // 半形英數字轉全形（執行時才轉，原始碼裡只有半形）。
    private static string FullWidth(string s) =>
        new(s.Select(c => c is >= '!' and <= '~' ? (char)(c + 0xFEE0) : c == ' ' ? '　' : c).ToArray());

    private static SecretMatch Single(string text) => Assert.Single(SecretDetector.Find(text));

    private static string Original(string text, SecretMatch m) => text.Substring(m.Index, m.Length);

    // ---- F11：身分證 ----

    [Theory]
    [InlineData("A 123 456 789")]
    [InlineData("A12345-6789")]
    [InlineData("A12345\n6789")]
    [InlineData("A12345\r\n6789")]
    [InlineData("A1234.56789")]
    [InlineData("A123​456789")]       // 零寬空白
    [InlineData("A123­456⁠789")] // 軟連字號、word joiner
    [InlineData("A123–456–789")] // en dash
    public void 身分證_分隔符號與零寬字元(string id)
    {
        var text = $"身分證：{id}，謝謝";
        var m = Single(text);
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("A12****789", m.Masked);
        Assert.Equal(id, Original(text, m));   // 位置對回原文，貼遮罩版才會整段換掉
    }

    [Fact]
    public void 身分證_全形()
    {
        var id = FullWidth("A123456789");
        var text = $"我的身分證是{id}喔";
        var m = Single(text);
        Assert.Equal(SecretKind.NationalId, m.Kind);
        Assert.Equal("A12****789", m.Masked);
        Assert.Equal(id, Original(text, m));
    }

    [Fact]
    public void 身分證_全形空白分隔() =>
        Assert.Equal(SecretKind.NationalId, Single(FullWidth("A 123 456 789")).Kind);

    [Theory]
    [InlineData("A 1 2 3 4 5 6 7 8 9")]   // 分隔符號太多
    [InlineData("A12345  6789")]           // 兩個空白不算同一個號碼
    [InlineData("A12345-6788")]            // 檢查碼錯
    [InlineData("XA 123 456 789")]         // 前面黏著字母
    [InlineData("A 123 456 7890")]         // 後面多一碼
    public void 身分證_不該命中(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind is SecretKind.NationalId or SecretKind.ResidentCertificate);

    // ---- F12：信用卡 ----

    [Theory]
    [InlineData("4111.1111.1111.1111", "4111********1111")]
    [InlineData("4111 1111\n1111 1111", "4111********1111")]   // 第二組後面折行
    [InlineData("4111 1111 1111 1111 12/30", "4111********1111")] // 後面接到期日
    [InlineData("3782 822463 10005", "3782*******0005")]
    [InlineData("3782.822463.10005", "3782*******0005")]
    [InlineData("5555​5555​5555​4444", "5555********4444")]
    public void 信用卡_分隔符號(string card, string masked)
    {
        var text = $"卡號 {card} 謝謝";
        var m = Single(text);
        Assert.Equal(SecretKind.CreditCard, m.Kind);
        Assert.Equal(masked, m.Masked);
        Assert.StartsWith(card[..4], Original(text, m));
    }

    [Fact]
    public void 信用卡_全形()
    {
        var card = FullWidth("4111-1111-1111-1111");
        var text = $"卡號：{card}";
        var m = Single(text);
        Assert.Equal(SecretKind.CreditCard, m.Kind);
        Assert.Equal("4111********1111", m.Masked);
        Assert.Equal(card, Original(text, m));
    }

    [Theory]
    [InlineData("4111111111\n111111")]        // 沒有分組的號碼中間換行：可能是兩行不相干的數字
    [InlineData("4111 1111-1111 1111")]       // 分隔符號不一致
    [InlineData("41111.11111.11111.1")]       // 分組不像卡號
    [InlineData("4111111111111112")]          // Luhn 錯
    public void 信用卡_不該命中(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.CreditCard);

    // ---- F12：手機 ----

    [Theory]
    [InlineData("886912000111")]
    [InlineData("+886 0912 000 111")]
    [InlineData("886-912-000-111")]
    [InlineData("0912.000.111")]
    [InlineData("0912\n000111")]
    [InlineData("(09)12000111")]
    [InlineData("(09) 1200-0111")]
    public void 手機_各種寫法(string phone)
    {
        var text = $"電話 {phone} 找我";
        var m = Single(text);
        Assert.Equal(SecretKind.MobilePhone, m.Kind);
        Assert.Equal("091****111", m.Masked);
        Assert.Equal(phone, Original(text, m));
    }

    [Fact]
    public void 手機_全形()
    {
        var phone = FullWidth("0955-666-777");
        var text = $"手機：{phone}";
        var m = Single(text);
        Assert.Equal(SecretKind.MobilePhone, m.Kind);
        Assert.Equal("095****777", m.Masked);
        Assert.Equal(phone, Original(text, m));
    }

    [Fact]
    public void 手機_括號區碼() => Assert.Equal("095****777", Single("(09)55666777").Masked);

    [Theory]
    [InlineData("(02)25556666")]          // 市話：沒有檢查碼又太常見，不偵測
    [InlineData("1886912000111")]         // 更長數字的一部分
    [InlineData("第 09 屆 12000111 號")]
    [InlineData("88691200011")]           // 少一碼
    public void 手機_不該命中(string text) =>
        Assert.DoesNotContain(SecretDetector.Find(text), m => m.Kind == SecretKind.MobilePhone);

    // ---- 分隔符號不能把不相干的數字湊成機密 ----

    [Theory]
    [InlineData("2024-01-15 2024-02-16 2024-03-17 2024-04-18")]
    [InlineData("4111-11-11 1111-11-11")]                 // 合起來剛好是測試卡號，但分組是日期
    [InlineData("4111.11.11\n1111.11.11")]
    [InlineData("會議日期：2023/11/22、2023/11/23、2023.11.24")]
    [InlineData("訂單 20240115-0001 20240115-0002 20240115-0003")]
    [InlineData("訂單編號 4000 1234 5678 99")]
    [InlineData("123e4567-e89b-12d3-a456-426614174000")]
    [InlineData("12345678-1234-1234-1234-123456789012")]
    [InlineData("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")]
    [InlineData("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg==")]
    [InlineData("版本 1.2.3.4，下一版 4.1.11.1111")]
    [InlineData("192.168.100.200 10.0.0.1 10.0.0.2 172.16.254.1")]
    [InlineData("今年 09 月 12 日到 345 號 678 室")]
    [InlineData("共 0912 人、345 隊、678 場")]
    [InlineData("價格 4,111 1,111 元")]
    public void 數字組合不該誤報(string text) => Assert.Empty(SecretDetector.Find(text));

    [Fact]
    public void 全形標點的中文不會誤報() =>
        Assert.Empty(SecretDetector.Find("明天（星期三）下午三點，在３樓開會：議程共１２項。"));

    // ---- 貼遮罩版：位置對回原文 ----

    [Fact]
    public void 貼遮罩版_全形與零寬字元整段換掉()
    {
        var text = $"ID {FullWidth("A123456789")} card 4111​1111​1111​1111 tel 886912000111.";
        var masked = PasteGuard.MaskText(text, SecretDetector.Find(text));
        Assert.Equal("ID A12****789 card 4111********1111 tel 091****111.", masked);
    }

    // ---- F15：JWT ----

    private static string B64Url(string json) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string FakeJwt(string header = """{"alg":"HS256","typ":"JWT"}""", string sig = "fake-signature-not-real_0123456789") =>
        $"{B64Url(header)}.{B64Url("""{"sub":"test-user","name":"Fake"}""")}.{sig}";

    [Fact]
    public void JWT_命中並遮罩()
    {
        var jwt = FakeJwt();
        var text = $"Authorization: Bearer {jwt}\n";
        var m = Single(text);
        Assert.Equal(SecretKind.ApiKey, m.Kind);
        Assert.Equal("JWT", m.Label);
        Assert.Equal("eyJ********789", m.Masked);
        Assert.Equal(jwt, Original(text, m));
    }

    [Fact]
    public void JWT_句尾句點與沒有簽章()
    {
        Assert.Equal("JWT", Single($"token 是 {FakeJwt()}.").Label);
        Assert.Equal("JWT", Single(FakeJwt("""{"alg":"none"}""", "")).Label);
    }

    [Theory]
    [InlineData("""{"typ":"JWT"}""")]   // 沒有 alg
    [InlineData("""{"alg":256}""")]     // alg 不是字串
    [InlineData("""{"alg":"HS256" """)] // 不是完整的 JSON
    public void JWT_header不對不算(string header) =>
        Assert.Empty(SecretDetector.Find(FakeJwt(header)));

    [Theory]
    [InlineData("eyJhbGciOi.not base64!.x")]
    [InlineData("eyJzzzzzzzzzzzz.abc.def")]       // header 解不出 JSON
    public void JWT_不像的字串不算(string text) => Assert.Empty(SecretDetector.Find(text));

    [Fact]
    public void JWT_五段的JWE不算() =>
        Assert.Empty(SecretDetector.Find($"{FakeJwt()}.{B64Url("x")}.{B64Url("y")}"));

    // ---- F10：超長文字 ----

    [Fact]
    public void 超長文字結尾的機密也找得到()
    {
        var filler = string.Concat(Enumerable.Repeat("這是一行很普通的紀錄，沒有機密。log line 0001\n", 150_000)); // 4.5M 字，超過 MaxScanLength，結尾走「頭尾」路徑
        var text = filler + "最後：A123456789 " + FullWidth("4111 1111 1111 1111");
        var sw = Stopwatch.StartNew();
        var found = SecretDetector.Find(text);
        sw.Stop();
        output.WriteLine($"{text.Length:N0} 字，{sw.ElapsedMilliseconds} ms");
        Assert.Equal([SecretKind.NationalId, SecretKind.CreditCard], found.Select(m => m.Kind));
        Assert.Equal(filler.Length + 3, found[0].Index);
    }

    [Fact]
    public void 中間開頭結尾都在上限內就全部分析()
    {
        var filler = new string('x', 300_000) + " ";
        var text = filler + "A123456789 " + filler + "0912000111 " + filler;
        Assert.Equal([SecretKind.NationalId, SecretKind.MobilePhone], SecretDetector.Find(text).Select(m => m.Kind));
    }

    [Fact]
    public void 超過上限時分析頭尾()
    {
        var half = SecretDetector.MaxScanLength / 2;
        var text = "A123456789 " + new string(' ', half) + "0912000111 " + new string(' ', half) + " 0955666777";
        var kinds = SecretDetector.Find(text).Select(m => m.Masked).ToArray();
        Assert.Equal(["A12****789", "095****777"], kinds);   // 中間那筆不在頭尾範圍內，刻意不分析
    }

    [Fact]
    public void 跨段邊界的機密只算一次而且位置正確()
    {
        foreach (var boundary in new[] { SecretDetector.SegmentStep, 2 * SecretDetector.SegmentStep })
        {
            for (var offset = -25; offset <= 2; offset++)
            {
                var pad = boundary + offset;
                var secret = "4111 1111 1111 1111";
                var text = new string('x', pad - 1) + " " + secret + " " + new string('y', 3 * SecretDetector.SegmentStep);
                var m = Assert.Single(SecretDetector.Find(text));
                Assert.Equal(pad, m.Index);
                Assert.Equal(secret.Length, m.Length);
            }
        }
    }

    [Fact]
    public void 跨段邊界的長_JWT()
    {
        var jwt = FakeJwt(sig: new string('s', 900));
        foreach (var offset in new[] { -jwt.Length + 1, -jwt.Length / 2, -3, 0 })
        {
            var pad = SecretDetector.SegmentStep + offset;
            var text = new string('x', pad - 1) + " " + jwt + " " + new string('y', SecretDetector.SegmentStep);
            var m = Assert.Single(SecretDetector.Find(text));
            Assert.Equal(pad, m.Index);
            Assert.Equal(jwt.Length, m.Length);
        }
    }

    [Fact]
    public void 超大或病態的剪貼簿不會卡住()
    {
        var huge = new (string Name, string Text)[]
        {
            ("空白", new string(' ', 4_000_000)),
            ("數字", new string('1', 4_000_000)),
            ("全形數字", new string('１', 4_000_000)),
            ("單碼數字組", string.Concat(Enumerable.Repeat("1 ", 2_000_000))),
            ("四碼數字組", string.Concat(Enumerable.Repeat("4111 ", 800_000))),
            ("點號數字", string.Concat(Enumerable.Repeat("4.", 2_000_000))),
            ("身分證樣子", string.Concat(Enumerable.Repeat("A1 ", 1_300_000))),
            ("滿滿身分證", string.Concat(Enumerable.Repeat("A123456789 ", 360_000))),
            ("滿滿全形手機", string.Concat(Enumerable.Repeat(FullWidth("0912-000-111 "), 300_000))),
            ("eyJ", string.Concat(Enumerable.Repeat("eyJ" + new string('a', 60) + ".", 60_000))),
            ("零寬字元", new string('​', 4_000_000)),
            ("中文", string.Concat(Enumerable.Repeat("今天天氣很好，（星期三）。", 300_000))),
            ("超過上限", new string('x', 20_000_000)),
        };
        foreach (var (name, text) in huge)
        {
            var sw = Stopwatch.StartNew();
            var found = SecretDetector.Find(text);
            sw.Stop();
            output.WriteLine($"{name}: {text.Length:N0} 字，{found.Count:N0} 筆，{sw.ElapsedMilliseconds} ms");
            Assert.True(sw.ElapsedMilliseconds < 5000, $"{name} took {sw.ElapsedMilliseconds} ms");
        }
    }
}
