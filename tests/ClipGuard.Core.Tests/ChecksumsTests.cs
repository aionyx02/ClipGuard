using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// 測試值都是依演算法湊出來的假號碼，不是任何真實的人或公司。
public class ChecksumsTests
{
    [Theory]
    [InlineData("A123456789")]   // 教科書範例
    [InlineData("B200000004")]
    [InlineData("F135792464")]
    [InlineData("a123456789")]   // 小寫首字母也接受
    [InlineData("A800000014")]   // 新式居留證（第 2 碼 8）
    [InlineData("Z900000008")]   // 新式居留證（第 2 碼 9）
    [InlineData("AB12345677")]   // 舊式居留證（第 2 碼字母）
    [InlineData("CD00000007")]
    public void 合法身分證與居留證(string id) => Assert.True(Checksums.IsValidTaiwanId(id));

    [Theory]
    [InlineData("A123456788")]   // 檢查碼錯
    [InlineData("A323456789")]   // 第 2 碼不能是 3
    [InlineData("A12345678")]    // 太短
    [InlineData("1123456789")]   // 首碼不是字母
    [InlineData("A12345678X")]
    [InlineData("AE12345677")]   // 舊式居留證第 2 碼只到 D
    public void 不合法身分證(string id) => Assert.False(Checksums.IsValidTaiwanId(id));

    [Theory]
    [InlineData("12345676")]     // 第 7 碼為 7，總和 40，新舊規則都過
    [InlineData("12345675")]     // 第 7 碼為 7，總和 39，靠 +1 規則
    [InlineData("24680241")]     // 總和 % 10 == 5：只有 2023 後「被 5 整除」的新規則才過
    [InlineData("13579134")]
    [InlineData("00000000")]
    public void 合法統一編號(string ban) => Assert.True(Checksums.IsValidBusinessId(ban));

    [Theory]
    [InlineData("12345678")]
    [InlineData("13579135")]
    [InlineData("20231122")]
    [InlineData("1234567")]
    [InlineData("1234567A")]
    public void 不合法統一編號(string ban) => Assert.False(Checksums.IsValidBusinessId(ban));

    [Theory]
    [InlineData("4111111111111111")]   // 各發卡組織公開的測試卡號
    [InlineData("5555555555554444")]
    [InlineData("378282246310005")]
    [InlineData("3530111333300000")]
    [InlineData("6011111111111117")]
    public void Luhn合法(string n) => Assert.True(Checksums.IsValidLuhn(n));

    [Theory]
    [InlineData("4111111111111112")]
    [InlineData("1234567812345678")]
    [InlineData("4")]
    public void Luhn不合法(string n) => Assert.False(Checksums.IsValidLuhn(n));
}
