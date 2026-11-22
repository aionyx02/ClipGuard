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
}
