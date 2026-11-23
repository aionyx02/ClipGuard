namespace ClipGuard.Core;

/// <summary>各種號碼的檢查碼驗證。輸入都假設已經去掉空白、連字號。</summary>
public static class Checksums
{
    // 身分證首字母對應的兩位數代碼。注意 I、O、W、X、Y、Z 不是照字母順序排。
    private const string IdLetters = "ABCDEFGHJKLMNPQRSTUVXYWZIO";

    private static int LetterCode(char c)
    {
        var i = IdLetters.IndexOf(char.ToUpperInvariant(c));
        return i < 0 ? -1 : 10 + i;
    }

    /// <summary>
    /// 國民身分證、新式居留證（第 2 碼 8/9，2021 起）、舊式居留證（第 2 碼 A–D）。
    /// 首字母轉兩位數 n1n2，權重 1,9，接著 8 個數字權重 8..1，最後檢查碼權重 1，總和要被 10 整除。
    /// 舊式居留證的第 2 碼字母取其代碼的個位數。
    /// </summary>
    public static bool IsValidTaiwanId(string id)
    {
        if (id.Length != 10) return false;
        var first = LetterCode(id[0]);
        if (first < 0) return false;

        int second;
        var c1 = char.ToUpperInvariant(id[1]);
        if (c1 is '1' or '2' or '8' or '9') second = c1 - '0';
        else if (c1 is >= 'A' and <= 'D') second = LetterCode(c1) % 10;
        else return false;

        var sum = first / 10 + first % 10 * 9 + second * 8;
        for (var i = 2; i < 10; i++)
        {
            if (!char.IsAsciiDigit(id[i])) return false;
            var weight = i == 9 ? 1 : 9 - i;   // 7,6,5,4,3,2,1 然後檢查碼 1
            sum += (id[i] - '0') * weight;
        }
        return sum % 10 == 0;
    }

    /// <summary>
    /// 營利事業統一編號。權重 1,2,1,2,1,2,4,1，每個乘積的十位與個位相加後加總。
    /// 財政部財政資訊中心〈營利事業統一編號檢查碼邏輯修正說明〉（110-12-22 發布）：
    /// 因統編號碼不足，檢查邏輯由「可被 10 整除」改為「可被 5 整除」，112 年 4 月後陸續配賦新號碼。
    /// 被 5 整除同時涵蓋舊號碼（被 10 整除者必被 5 整除）。
    /// 第 7 碼為 7 時 4×7=28 → 2+8=10，這一位可視為 1 或 0，兩種總和任一被 5 整除即可，
    /// 也就是 sum 或 sum+1 被 5 整除（以 10 計算時）。
    /// https://www.fia.gov.tw/singlehtml/3?cntId=c4d9cff38c8642ef8872774ee9987283
    /// </summary>
    public static bool IsValidBusinessId(string ban)
    {
        if (ban.Length != 8) return false;
        ReadOnlySpan<int> weights = [1, 2, 1, 2, 1, 2, 4, 1];
        var sum = 0;
        for (var i = 0; i < 8; i++)
        {
            if (!char.IsAsciiDigit(ban[i])) return false;
            var p = (ban[i] - '0') * weights[i];
            sum += p / 10 + p % 10;
        }
        return sum % 5 == 0 || (ban[6] == '7' && (sum + 1) % 5 == 0);
    }

    /// <summary>Luhn（mod 10），信用卡號用。</summary>
    public static bool IsValidLuhn(string digits)
    {
        if (digits.Length < 2) return false;
        var sum = 0;
        var doubleIt = false;
        for (var i = digits.Length - 1; i >= 0; i--)
        {
            if (!char.IsAsciiDigit(digits[i])) return false;
            var d = digits[i] - '0';
            if (doubleIt) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            doubleIt = !doubleIt;
        }
        return sum % 10 == 0;
    }

    // ---------- #27：通用包與國家包 ----------

    /// <summary>
    /// IBAN 各國的總長度（SWIFT IBAN Registry）。不在表裡的國家代碼一律不算，所以隨便一串「兩個字母＋數字」
    /// 必須同時碰上存在的國家、剛好的長度和 mod-97，才會被當成 IBAN。與 extension/lib/pii.js 的 IBAN_LENGTHS 相同。
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, int> IbanLengths = new Dictionary<string, int>(StringComparer.Ordinal)
    {
        ["AD"] = 24, ["AE"] = 23, ["AL"] = 28, ["AT"] = 20, ["AZ"] = 28, ["BA"] = 20, ["BE"] = 16, ["BG"] = 22,
        ["BH"] = 22, ["BI"] = 27, ["BR"] = 29, ["BY"] = 28, ["CH"] = 21, ["CR"] = 22, ["CY"] = 28, ["CZ"] = 24,
        ["DE"] = 22, ["DJ"] = 27, ["DK"] = 18, ["DO"] = 28, ["EE"] = 20, ["EG"] = 29, ["ES"] = 24, ["FI"] = 18,
        ["FK"] = 18, ["FO"] = 18, ["FR"] = 27, ["GB"] = 22, ["GE"] = 22, ["GI"] = 23, ["GL"] = 18, ["GR"] = 27,
        ["GT"] = 28, ["HN"] = 28, ["HR"] = 21, ["HU"] = 28, ["IE"] = 22, ["IL"] = 23, ["IQ"] = 23, ["IS"] = 26,
        ["IT"] = 27, ["JO"] = 30, ["KW"] = 30, ["KZ"] = 20, ["LB"] = 28, ["LC"] = 32, ["LI"] = 21, ["LT"] = 20,
        ["LU"] = 20, ["LV"] = 21, ["LY"] = 25, ["MC"] = 27, ["MD"] = 24, ["ME"] = 22, ["MK"] = 19, ["MN"] = 20,
        ["MR"] = 27, ["MT"] = 31, ["MU"] = 30, ["NI"] = 28, ["NL"] = 18, ["NO"] = 15, ["OM"] = 23, ["PK"] = 24,
        ["PL"] = 28, ["PS"] = 29, ["PT"] = 25, ["QA"] = 29, ["RO"] = 24, ["RS"] = 22, ["RU"] = 33, ["SA"] = 24,
        ["SC"] = 31, ["SD"] = 18, ["SE"] = 24, ["SI"] = 19, ["SK"] = 24, ["SM"] = 27, ["SO"] = 23, ["ST"] = 25,
        ["SV"] = 28, ["TL"] = 23, ["TN"] = 24, ["TR"] = 26, ["UA"] = 29, ["VA"] = 22, ["VG"] = 24, ["XK"] = 20,
        ["YE"] = 30,
    };

    /// <summary>
    /// IBAN（ISO 13616）：國家代碼在表裡、總長度符合該國、檢查碼 02–98，
    /// 前 4 碼搬到最後、字母換成 10–35 之後 mod 97 = 1。輸入要先去掉空白、轉大寫。
    /// </summary>
    public static bool IsValidIban(string iban)
    {
        if (iban.Length < 4 || !IbanLengths.TryGetValue(iban[..2], out var length) || iban.Length != length) return false;
        if (!char.IsAsciiDigit(iban[2]) || !char.IsAsciiDigit(iban[3])) return false;
        var check = (iban[2] - '0') * 10 + (iban[3] - '0');
        if (check is < 2 or > 98) return false;
        var mod = 0;
        for (var k = 0; k < iban.Length; k++)
        {
            var c = iban[(k + 4) % iban.Length];
            if (char.IsAsciiDigit(c)) mod = (mod * 10 + (c - '0')) % 97;
            else if (char.IsAsciiLetterUpper(c)) mod = (mod * 100 + (c - 'A' + 10)) % 97;
            else return false;
        }
        return mod == 1;
    }

    /// <summary>
    /// 中國居民身分證（GB 11643-1999）：18 碼，前 17 碼權重 7,9,10,5,8,4,2,1,6,3,7,9,10,5,8,4,2，
    /// 總和 mod 11 對應檢查碼「10X98765432」（ISO 7064 MOD 11-2）。另外檢查出生日期是真的日期。
    /// </summary>
    public static bool IsValidChinaResidentId(string id)
    {
        if (id.Length != 18) return false;
        ReadOnlySpan<int> weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
        var sum = 0;
        for (var i = 0; i < 17; i++)
        {
            if (!char.IsAsciiDigit(id[i])) return false;
            sum += (id[i] - '0') * weights[i];
        }
        if ("10X98765432"[sum % 11] != char.ToUpperInvariant(id[17])) return false;
        return IsDate(int.Parse(id.AsSpan(6, 4)), int.Parse(id.AsSpan(10, 2)), int.Parse(id.AsSpan(12, 2)));
    }

    /// <summary>
    /// 日本個人番號（マイナンバー）：12 碼。前 11 碼從右邊數第 n 碼乘 Qn（n ≤ 6 時 n+1，否則 n−5），
    /// 總和 mod 11 ≤ 1 時檢查碼是 0，否則是 11 − 餘數（番号法施行令第 8 條）。
    /// </summary>
    public static bool IsValidMyNumber(string digits)
    {
        if (digits.Length != 12 || !digits.All(char.IsAsciiDigit)) return false;
        var sum = 0;
        for (var n = 1; n <= 11; n++)
            sum += (digits[11 - n] - '0') * (n <= 6 ? n + 1 : n - 5);
        var r = sum % 11;
        return digits[11] - '0' == (r <= 1 ? 0 : 11 - r);
    }

    /// <summary>
    /// 香港身分證：1–2 個字母 + 6 碼數字 + 檢查碼（0–9 或 A）。字母 A–Z = 10–35，只有一個字母時前面補空白（= 36），
    /// 權重 9..2 加上檢查碼（A = 10）要被 11 整除。輸入不含括號。
    /// </summary>
    public static bool IsValidHongKongId(string id)
    {
        if (id.Length is not (8 or 9)) return false;
        var letters = id.Length - 7;
        var sum = letters == 1 ? 36 * 9 : 0;
        for (var i = 0; i < letters; i++)
        {
            if (!char.IsAsciiLetterUpper(id[i])) return false;
            sum += (id[i] - 'A' + 10) * (letters == 1 ? 8 : 9 - i);
        }
        for (var i = 0; i < 6; i++)
        {
            var c = id[letters + i];
            if (!char.IsAsciiDigit(c)) return false;
            sum += (c - '0') * (7 - i);
        }
        var last = id[^1];
        var check = last == 'A' ? 10 : char.IsAsciiDigit(last) ? last - '0' : -1;
        return check >= 0 && (sum + check) % 11 == 0;
    }

    /// <summary>
    /// 新加坡 NRIC／FIN：S、T、F、G、M + 7 碼 + 檢查字母。權重 2,7,6,5,4,3,2，T、G 加 4，M 加 3，
    /// 總和 mod 11 查表：S/T「JZIHGFEDCBA」、F/G「XWUTRQPNMLK」、M「XWUTRQPNJLK」（2022 年起的 M 系列 FIN）。
    /// </summary>
    public static bool IsValidSingaporeNric(string id)
    {
        if (id.Length != 9) return false;
        ReadOnlySpan<int> weights = [2, 7, 6, 5, 4, 3, 2];
        var sum = 0;
        for (var i = 0; i < 7; i++)
        {
            if (!char.IsAsciiDigit(id[i + 1])) return false;
            sum += (id[i + 1] - '0') * weights[i];
        }
        var (offset, table) = id[0] switch
        {
            'S' => (0, "JZIHGFEDCBA"),
            'T' => (4, "JZIHGFEDCBA"),
            'F' => (0, "XWUTRQPNMLK"),
            'G' => (4, "XWUTRQPNMLK"),
            'M' => (3, "XWUTRQPNJLK"),
            _ => (-1, ""),
        };
        return offset >= 0 && table[(sum + offset) % 11] == id[8];
    }

    /// <summary>
    /// 美國 SSN 沒有檢查碼，只排除 SSA 不會發的範圍：區碼 000、666、900–999，組號 00，序號 0000。輸入是 9 碼數字。
    /// </summary>
    public static bool IsPlausibleUsSsn(string digits)
    {
        if (digits.Length != 9 || !digits.All(char.IsAsciiDigit)) return false;
        var area = int.Parse(digits.AsSpan(0, 3));
        return area is not (0 or 666 or >= 900) && digits[3..5] != "00" && digits[5..] != "0000";
    }

    // ITU-T E.164 已分配的國碼：1、7 是一碼，其餘列出兩碼和三碼的。與 extension/lib/pii.js 相同。
    private static readonly HashSet<string> CountryCodes2 =
    [
        "20", "27", "30", "31", "32", "33", "34", "36", "39", "40", "41", "43", "44", "45", "46", "47", "48", "49",
        "51", "52", "53", "54", "55", "56", "57", "58", "60", "61", "62", "63", "64", "65", "66", "81", "82", "84",
        "86", "90", "91", "92", "93", "94", "95", "98",
    ];

    private static readonly HashSet<string> CountryCodes3 = BuildCountryCodes3();

    private static HashSet<string> BuildCountryCodes3()
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        void Range(int from, int to)
        {
            for (var c = from; c <= to; c++) set.Add(c.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }
        foreach (var c in (int[])[211, 212, 213, 216, 218, 290, 291, 297, 298, 299, 389, 420, 421, 423, 670, 800, 808, 850,
                     852, 853, 855, 856, 870, 878, 880, 881, 882, 883, 886, 888, 979, 998])
            Range(c, c);
        Range(220, 258); Range(260, 269); Range(350, 359); Range(370, 383); Range(385, 387);
        Range(500, 509); Range(590, 599); Range(672, 683); Range(685, 692); Range(960, 968); Range(970, 977); Range(992, 996);
        return set;
    }

    /// <summary>
    /// 國際電話（E.164）：「+」後面的數字。國碼要是已分配的，總長 8–15 碼；
    /// +1（北美）和 +7 一定是 11 碼，北美的區碼第一碼是 2–9。沒有檢查碼，所以規則檔另外要求號碼以 + 開頭。
    /// </summary>
    public static bool IsPlausibleE164(string digits)
    {
        if (digits.Length is < 8 or > 15 || !digits.All(char.IsAsciiDigit)) return false;
        return digits[0] switch
        {
            '1' => digits.Length == 11 && digits[1] >= '2',
            '7' => digits.Length == 11,
            _ => CountryCodes2.Contains(digits[..2]) || CountryCodes3.Contains(digits[..3]),
        };
    }

    private static bool IsDate(int year, int month, int day) =>
        year is >= 1800 and <= 2199 && month is >= 1 and <= 12 && day >= 1 && day <= DateTime.DaysInMonth(year, month);
}
