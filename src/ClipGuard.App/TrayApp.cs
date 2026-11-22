using System.Runtime.InteropServices;
using ClipGuard.Core;

namespace ClipGuard.App;

internal sealed class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly ClipboardMonitor _monitor;
    private readonly ToolStripMenuItem _restoreItem;

    // 被清掉的內容只留在記憶體，讓使用者誤判時可以拿回來；不寫檔、不記 log。
    private string? _quarantined;
    // 自己寫入剪貼簿時會再收到一次通知，用這個旗標略過。
    private bool _selfWrite;

    public TrayApp()
    {
        _restoreItem = new ToolStripMenuItem("還原被清除的內容", null, (_, _) => Restore()) { Enabled = false };

        var menu = new ContextMenuStrip();
        menu.Items.Add(_restoreItem);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("結束", null, (_, _) => ExitThread());

        _tray = new NotifyIcon
        {
            Icon = SystemIcons.Shield,
            Text = "ClipGuard：剪貼簿防護中",
            ContextMenuStrip = menu,
            Visible = true,
        };

        _tray.BalloonTipClicked += (_, _) => { var a = _balloonClick; _balloonClick = null; a?.Invoke(); };
        _tray.BalloonTipClosed += (_, _) => _balloonClick = null;

        _monitor = new ClipboardMonitor();
        _monitor.ClipboardChanged += OnClipboardChanged;
    }

    private void OnClipboardChanged(object? sender, EventArgs e)
    {
        if (_selfWrite) { _selfWrite = false; return; }

        var text = TryGetText();
        if (text is null) return;

        var verdict = CommandDetector.Analyze(text);
        if (verdict.Level == ThreatLevel.None) return;

        // 白話說明與解碼內容只放進通知，不寫檔、不記 log。
        var explanation = CommandExplainer.Explain(text);
        switch (verdict.Level)
        {
            case ThreatLevel.Malicious:
                _quarantined = text;
                _restoreItem.Enabled = true;
                _selfWrite = true;
                TryClear();
                Notify(ToolTipIcon.Error, "已攔截可疑的「貼上執行」指令",
                    ComposeBody("剪貼簿已清空，正常網站不會要你按 Win+R 貼上指令。", explanation,
                        "若確定安全，點這則通知或從系統匣選單還原。"),
                    onClick: Restore);
                break;

            case ThreatLevel.Suspicious:
                Notify(ToolTipIcon.Warning, "剪貼簿裡是會執行程式的指令",
                    ComposeBody("貼上前請確認來源可信。", explanation, null));
                break;
        }
    }

    // 通知內文上限 255 字元（NOTIFYICONDATA.szInfo），把白話說明塞進頭尾之間的空間。
    private const int MaxBodyLength = 255;

    private static string ComposeBody(string head, CommandExplanation explanation, string? tail)
    {
        var room = MaxBodyLength - head.Length - 1 - (tail is null ? 0 : tail.Length + 1);
        var body = head + "\n" + explanation.ToDisplayText(room);
        return tail is null ? body : body + "\n" + tail;
    }

    private void Restore()
    {
        if (_quarantined is null) return;
        _selfWrite = true;
        if (TrySetText(_quarantined))
        {
            _quarantined = null;
            _restoreItem.Enabled = false;
        }
        else
        {
            _selfWrite = false;
        }
    }

    // 點通知時要做的事（例如還原）；每則新通知都會覆蓋，通知關閉後清掉。
    private Action? _balloonClick;

    private void Notify(ToolTipIcon icon, string title, string body) => Notify(icon, title, body, onClick: null);

    private void Notify(ToolTipIcon icon, string title, string body, Action? onClick)
    {
        _balloonClick = onClick;
        if (title.Length > 63) title = title[..62] + "…";   // szInfoTitle 上限
        if (body.Length > MaxBodyLength) body = body[..(MaxBodyLength - 1)] + "…";
        _tray.ShowBalloonTip(8000, title, body, icon);
    }

    // 剪貼簿可能正被別的程式開著，短暫重試幾次。
    private static T? Retry<T>(Func<T> action)
    {
        for (var i = 0; i < 5; i++)
        {
            try { return action(); }
            catch (ExternalException) { Thread.Sleep(30); }
        }
        return default;
    }

    private static string? TryGetText() =>
        Retry(() => Clipboard.ContainsText() ? Clipboard.GetText() : null);

    private static void TryClear() => Retry(() => { Clipboard.Clear(); return true; });

    private static bool TrySetText(string text) => Retry(() => { Clipboard.SetText(text); return true; });

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _monitor.Dispose();
            _tray.Visible = false;
            _tray.Dispose();
        }
        base.Dispose(disposing);
    }
}
