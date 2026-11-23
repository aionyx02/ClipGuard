namespace ClipGuard.Core;

public enum NotificationLevel
{
    Warning,
    Error,
}

/// <param name="Restorable">「已攔截，點擊還原」那一則；點下去要還原隔離區的內容。</param>
public sealed record TrayNotification(NotificationLevel Level, string Title, string Body, bool Restorable = false);

/// <summary>
/// 決定通知現在顯示、稍後顯示，還是作廢（#24 F18）。
/// </summary>
/// <param name="Show">現在要顯示的通知；沒有就是 null。</param>
/// <param name="ReplaceVisible">上一則可能還在畫面上或在 Windows 的佇列裡，要先把它撤掉再顯示，不能排在它後面。</param>
/// <param name="RetryIn">有通知在等：過這麼久再呼叫 <see cref="NotificationThrottle.Flush"/>。</param>
public readonly record struct NotificationDecision(TrayNotification? Show, bool ReplaceVisible, TimeSpan? RetryIn);

/// <summary>
/// 通知節流（#24 F18）。Windows 會把通知排隊依序顯示，連續複製時，幾十秒後跳出的都是早就過期的通知。
/// 這裡保證：
/// <list type="bullet">
/// <item>同一時間最多一則在畫面上：新的直接取代舊的（App 先撤掉舊的），不排在後面。</item>
/// <item>兩則之間至少隔 <see cref="DefaultMinInterval"/>；期間進來的只留最新一則，剪貼簿一換就作廢，不會顯示過期內容。</item>
/// <item>攔截通知（可還原）一律立刻顯示、不會被作廢；顯示期間只有 Error 等級能取代它，Warning 要等它的顯示時間過去（P2）。
/// 就算通知被取代，系統匣選單的「還原」仍然可以用。</item>
/// </list>
/// 純邏輯，時間由外部注入；不保存通知以外的任何內容（通知本身只有遮罩後的字串，P3、P4）。
/// </summary>
public sealed class NotificationThrottle
{
    public static readonly TimeSpan DefaultMinInterval = TimeSpan.FromSeconds(1);
    // Windows 預設通知顯示 5 秒（「輔助工具 > 通知顯示時間」可調長），抓寬一點。
    public static readonly TimeSpan DefaultVisibleFor = TimeSpan.FromSeconds(6);

    private readonly TimeProvider _clock;
    private readonly TimeSpan _minInterval;
    private readonly TimeSpan _visibleFor;

    private DateTimeOffset? _lastShownAt;
    private bool _lastShownRestorable;
    private TrayNotification? _pending;

    public NotificationThrottle(TimeProvider? clock = null, TimeSpan? minInterval = null, TimeSpan? visibleFor = null)
    {
        _clock = clock ?? TimeProvider.System;
        _minInterval = minInterval ?? DefaultMinInterval;
        _visibleFor = visibleFor ?? DefaultVisibleFor;
    }

    /// <summary>還在等著顯示的通知。</summary>
    public TrayNotification? Pending => _pending;

    /// <summary>剪貼簿內容換了：還沒顯示的通知講的是舊內容，作廢。</summary>
    public void OnClipboardChanged() => _pending = null;

    public NotificationDecision Submit(TrayNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        var now = _clock.GetUtcNow();
        if (notification.Restorable) return ShowNow(notification, now);

        // 等待區只有一格，留最新的；但還在等的 Error 不讓 Warning 蓋掉。
        if (_pending is null || _pending.Level <= notification.Level)
            _pending = notification;
        var due = DueAt(_pending);
        return due <= now ? ShowNow(_pending, now) : new NotificationDecision(null, false, due - now);
    }

    /// <summary>計時器到了時呼叫。等待中的通知到期就回傳它，還沒到期就回傳還要等多久。</summary>
    public NotificationDecision Flush()
    {
        if (_pending is null) return default;
        var now = _clock.GetUtcNow();
        var due = DueAt(_pending);
        return due <= now ? ShowNow(_pending, now) : new NotificationDecision(null, false, due - now);
    }

    private DateTimeOffset DueAt(TrayNotification n)
    {
        if (_lastShownAt is not { } last) return DateTimeOffset.MinValue;
        var due = last + _minInterval;
        // 攔截通知還在畫面上時，Warning 等它顯示完，不能把「點擊還原」蓋掉。
        if (_lastShownRestorable && n.Level == NotificationLevel.Warning) due = last + _visibleFor;
        return due;
    }

    private NotificationDecision ShowNow(TrayNotification n, DateTimeOffset now)
    {
        var replace = _lastShownAt is { } last && now - last < _visibleFor;
        _lastShownAt = now;
        _lastShownRestorable = n.Restorable;
        _pending = null;
        return new NotificationDecision(n, replace, null);
    }
}
