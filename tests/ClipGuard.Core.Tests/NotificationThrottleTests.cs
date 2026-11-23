using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class NotificationThrottleTests
{
    private sealed class FakeClock : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => Now;
        public void Advance(int ms) => Now = Now.AddMilliseconds(ms);
    }

    private readonly FakeClock _clock = new();

    // 間隔 1 秒、顯示 6 秒（預設值）。
    private NotificationThrottle NewThrottle() =>
        new(_clock, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(6));

    private static TrayNotification Warn(string title) => new(NotificationLevel.Warning, title, "");
    private static TrayNotification Error(string title) => new(NotificationLevel.Error, title, "");
    private static TrayNotification Blocked(string title) => new(NotificationLevel.Error, title, "", Restorable: true);

    [Fact]
    public void 第一則立刻顯示且不用撤掉任何東西()
    {
        var t = NewThrottle();
        var d = t.Submit(Warn("a"));
        Assert.Equal("a", d.Show?.Title);
        Assert.False(d.ReplaceVisible);
        Assert.Null(d.RetryIn);
    }

    [Fact]
    public void 間隔內的通知先等_到期才顯示並取代畫面上的那則()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(300);

        var d = t.Submit(Warn("b"));
        Assert.Null(d.Show);
        Assert.Equal(TimeSpan.FromMilliseconds(700), d.RetryIn);

        _clock.Advance(699);
        Assert.Null(t.Flush().Show);
        _clock.Advance(1);
        var shown = t.Flush();
        Assert.Equal("b", shown.Show?.Title);
        Assert.True(shown.ReplaceVisible);   // a 可能還在畫面上：撤掉，不排在它後面
        Assert.Null(t.Pending);
    }

    [Fact]
    public void 連續複製只留最新一則()
    {
        var t = NewThrottle();
        t.Submit(Warn("1"));
        for (var i = 2; i <= 10; i++)
        {
            _clock.Advance(50);
            t.OnClipboardChanged();
            t.Submit(Warn(i.ToString()));
        }
        _clock.Advance(1000);
        Assert.Equal("10", t.Flush().Show?.Title);
        Assert.Null(t.Flush().Show);
    }

    [Fact]
    public void 剪貼簿換了內容_還沒顯示的通知作廢()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(100);
        t.Submit(Warn("b"));
        t.OnClipboardChanged();   // 又複製了不需要通知的東西
        _clock.Advance(5000);
        Assert.Null(t.Flush().Show);
    }

    [Fact]
    public void 過了顯示時間就不用撤掉舊的()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(6000);
        var d = t.Submit(Warn("b"));
        Assert.Equal("b", d.Show?.Title);
        Assert.False(d.ReplaceVisible);
    }

    [Fact]
    public void 攔截通知一律立刻顯示()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(10);
        var d = t.Submit(Blocked("blocked"));
        Assert.Equal("blocked", d.Show?.Title);
        Assert.True(d.ReplaceVisible);
    }

    [Fact]
    public void 攔截通知顯示期間_Warning要等它顯示完()
    {
        var t = NewThrottle();
        t.Submit(Blocked("blocked"));
        _clock.Advance(1500);   // 已超過一般間隔，但攔截通知還在畫面上

        var d = t.Submit(Warn("w"));
        Assert.Null(d.Show);
        Assert.Equal(TimeSpan.FromMilliseconds(4500), d.RetryIn);

        _clock.Advance(4500);
        var shown = t.Flush();
        Assert.Equal("w", shown.Show?.Title);
        Assert.False(shown.ReplaceVisible);   // 攔截通知已經顯示完了，不用撤
    }

    [Fact]
    public void 攔截通知顯示期間_等著的Warning在剪貼簿換掉後作廢()
    {
        var t = NewThrottle();
        t.Submit(Blocked("blocked"));
        _clock.Advance(1500);
        t.Submit(Warn("w"));
        t.OnClipboardChanged();
        _clock.Advance(10_000);
        Assert.Null(t.Flush().Show);
    }

    [Fact]
    public void 攔截通知顯示期間_Error只要等一般間隔()
    {
        var t = NewThrottle();
        t.Submit(Blocked("blocked"));
        _clock.Advance(200);
        var d = t.Submit(Error("entry"));   // 例如剛攔截完就打開 Win+R
        Assert.Equal(TimeSpan.FromMilliseconds(800), d.RetryIn);
        _clock.Advance(800);
        Assert.Equal("entry", t.Flush().Show?.Title);
    }

    [Fact]
    public void 新的攔截通知取代舊的攔截通知()
    {
        var t = NewThrottle();
        t.Submit(Blocked("1"));
        _clock.Advance(100);
        t.OnClipboardChanged();
        var d = t.Submit(Blocked("2"));
        Assert.Equal("2", d.Show?.Title);
        Assert.True(d.ReplaceVisible);
    }

    [Fact]
    public void 攔截通知不會因為剪貼簿換掉而作廢()
    {
        // 攔截通知從不進等待區，所以 OnClipboardChanged 不會吃掉它。
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(10);
        Assert.NotNull(t.Submit(Blocked("blocked")).Show);
        t.OnClipboardChanged();
        Assert.Null(t.Pending);
    }

    [Fact]
    public void 等待中的Error不會被Warning蓋掉()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(100);
        t.Submit(Error("e"));
        _clock.Advance(100);
        t.Submit(Warn("w"));
        _clock.Advance(1000);
        Assert.Equal("e", t.Flush().Show?.Title);
    }

    [Fact]
    public void 到期後才進來的通知直接顯示_連同等待中的較高等級()
    {
        var t = NewThrottle();
        t.Submit(Warn("a"));
        _clock.Advance(100);
        t.Submit(Error("e"));
        _clock.Advance(2000);   // 計時器晚到了
        var d = t.Submit(Warn("w"));
        Assert.Equal("e", d.Show?.Title);
        Assert.Null(t.Pending);
    }

    [Fact]
    public void 沒有等待中的通知時Flush什麼都不做()
    {
        var t = NewThrottle();
        var d = t.Flush();
        Assert.Null(d.Show);
        Assert.Null(d.RetryIn);
    }
}
