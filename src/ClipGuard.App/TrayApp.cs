using System.Runtime.InteropServices;
using ClipGuard.Core;

namespace ClipGuard.App;

internal sealed class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly ClipboardMonitor _monitor;
    private readonly ToolStripMenuItem _restoreItem;
    private readonly ForegroundWatcher _foreground;
    private readonly EntryWarningGate _entryGate = new();

    // 判定、隔離與還原的狀態都在 Core；被清掉的內容只留在記憶體，不寫檔、不記 log。
    private readonly ClipboardGuardState _state = new();
    private readonly WalletSwapDetector _walletSwap = new();

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

        _foreground = new ForegroundWatcher();
        _foreground.ForegroundChanged += OnForegroundChanged;

        // 啟動前（或啟動途中）就已複製的內容不會觸發通知，等訊息迴圈開始後先檢查一次。
        var startup = new System.Windows.Forms.Timer { Interval = 1 };
        startup.Tick += (_, _) => { startup.Dispose(); OnClipboardChanged(null, EventArgs.Empty); };
        startup.Start();
    }

    private void OnClipboardChanged(object? sender, EventArgs e)
    {
        var text = TryGetText();
        var action = _state.OnClipboardText(text);

        // 白話說明與解碼內容只放進通知，不寫檔、不記 log。只有需要通知時才產生。
        var explanation = action is ClipboardAction.Quarantine or ClipboardAction.WarnSuspicious && text is not null
            ? CommandExplainer.Explain(text)
            : null;

        switch (action)
        {
            case ClipboardAction.Quarantine:
                _restoreItem.Enabled = true;
                TryClear();
                Notify(ToolTipIcon.Error, "已攔截可疑的「貼上執行」指令",
                    ComposeBody("剪貼簿已清空，正常網站不會要你按 Win+R 貼上指令。", explanation!,
                        "若確定安全，點這則通知或從系統匣選單還原。"),
                    onClick: Restore);
                break;

            case ClipboardAction.WarnSuspicious:
                Notify(ToolTipIcon.Warning, "剪貼簿裡是會執行程式的指令",
                    ComposeBody("貼上前請確認來源可信。", explanation!, null));
                break;
        }

        // 指令警告優先：已經跳出攔截或提醒時，不再用隱藏字元通知蓋掉它（攔截通知帶有「點擊還原」）。
        if (text is not null)
            CheckHiddenCharsAndWalletSwap(text, notifyHiddenChars: action == ClipboardAction.None);
    }

    // 隱藏字元（#5）與錢包地址掉包（#6）。通知不顯示地址或原文。
    private void CheckHiddenCharsAndWalletSwap(string text, bool notifyHiddenChars)
    {
        if (_walletSwap.Observe(text) is { } swap)
        {
            Notify(ToolTipIcon.Error, "錢包地址可能被掉包",
                $"剛複製的 {swap.Currency} 地址在 {swap.Elapsed.TotalMilliseconds:0} 毫秒內被換成另一個地址，可能有剪貼簿劫持惡意程式。\n"
                + "請勿貼上；假地址常與原地址頭尾相同，請逐字核對並掃毒。");
            return;
        }

        if (!notifyHiddenChars) return;
        var hidden = HiddenCharDetector.Analyze(text);
        if (hidden.Level != ThreatLevel.None)
            Notify(ToolTipIcon.Warning, "剪貼簿裡有看不見或偽裝的字元",
                "貼上前請確認內容。\n" + string.Join("、", hidden.Reasons));
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
        if (_state.BeginRestore() is not { } text) return;
        var ok = TrySetText(text);
        _state.EndRestore(ok);
        _restoreItem.Enabled = _state.Quarantined is not null;
    }

    // Win+R、檔案總管、終端機等執行入口被叫到前景時，依剪貼簿狀態再警告一次。
    private void OnForegroundChanged(ForegroundWatcher.WindowInfo w)
    {
        var warning = ExecutionEntryGuard.Decide(w.ClassName, w.Title, w.ProcessName, _state.Level, _state.QuarantineActive);
        if (warning is null || !_entryGate.TryEnter(w.Handle, _state.Generation)) return;
        Notify(warning.Level == ThreatLevel.Malicious ? ToolTipIcon.Error : ToolTipIcon.Warning, warning.Title, warning.Body);
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
            _foreground.Dispose();
            _monitor.Dispose();
            _tray.Visible = false;
            _tray.Dispose();
        }
        base.Dispose(disposing);
    }
}
