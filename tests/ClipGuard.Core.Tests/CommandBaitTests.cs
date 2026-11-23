using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

// #27：多語系的誘餌註解。指令在執行時用片段組合（§8），本身只是「呼叫 PowerShell」的執行訊號（Suspicious），
// 加上誘餌註解才變成 Malicious；同一個指令配上該語言的一般註解要維持 Suspicious。
public class CommandBaitTests
{
    private static readonly string Command = string.Concat("pw", "sh") + " -c \"Get-Date\"";

    private static ThreatLevel Level(string comment) => CommandDetector.Analyze($"{Command} # {comment}").Level;

    [Fact]
    public void 基本指令本身只是提醒() => Assert.Equal(ThreatLevel.Suspicious, CommandDetector.Analyze(Command).Level);

    [Theory]
    [InlineData("zh-TW", "我不是機器人 驗證 ID: 4821")]
    [InlineData("zh-CN", "我不是机器人 验证 ID: 4821")]
    [InlineData("zh-CN", "人机验证")]
    [InlineData("ja", "私はロボットではありません")]
    [InlineData("ja", "reCAPTCHA 認証 ID: 4821")]
    [InlineData("ja", "人間であることを確認してください")]
    [InlineData("ko", "나는 로봇이 아닙니다")]
    [InlineData("ko", "인증 ID: 4821")]
    [InlineData("ko", "사람인지 확인")]
    [InlineData("es", "No soy un robot - verificación ID: 4821")]
    [InlineData("pt", "Não sou um robô")]
    [InlineData("pt", "ID de verificação: 4821")]
    [InlineData("fr", "Je ne suis pas un robot")]
    [InlineData("fr", "Vérification ID : 4821")]
    [InlineData("de", "Ich bin kein Roboter")]
    [InlineData("de", "Verifizierung ID: 4821")]
    [InlineData("it", "Non sono un robot")]
    [InlineData("ru", "Я не робот")]
    [InlineData("ru", "Верификация ID: 4821")]
    [InlineData("ru", "Введите капчу")]
    [InlineData("vi", "Tôi không phải là người máy")]
    [InlineData("vi", "Xác minh ID: 4821")]
    [InlineData("id", "Saya bukan robot - verifikasi ID: 4821")]
    [InlineData("tr", "Robot değilim")]
    public void 誘餌註解(string language, string comment)
    {
        Assert.True(Level(comment) == ThreatLevel.Malicious, language);
        Assert.Contains("誘餌註解（假裝是人機驗證）", CommandDetector.Analyze($"{Command} # {comment}").Reasons);
    }

    [Theory]
    [InlineData("zh-CN", "显示当前日期")]
    [InlineData("ja", "日付を表示")]
    [InlineData("ja", "認証トークンを更新する")]      // 認証 單獨出現不算
    [InlineData("ko", "날짜 표시")]
    [InlineData("ko", "인증서 설치")]                  // 인증서 = 憑證
    [InlineData("es", "mostrar la fecha")]
    [InlineData("pt", "mostrar a data")]
    [InlineData("fr", "afficher la date")]
    [InlineData("de", "Datum anzeigen")]
    [InlineData("ru", "показать дату")]
    [InlineData("vi", "hiển thị ngày")]
    [InlineData("id", "tampilkan tanggal")]
    public void 一般註解不算誘餌(string language, string comment) =>
        Assert.True(Level(comment) == ThreatLevel.Suspicious, language);

    [Theory]
    [InlineData("私はロボットではありません")]
    [InlineData("나는 로봇이 아닙니다")]
    [InlineData("Я не робот # 验证")]
    public void 沒有指令的句子不處理(string text) => Assert.Equal(ThreatLevel.None, CommandDetector.Analyze(text).Level);
}
