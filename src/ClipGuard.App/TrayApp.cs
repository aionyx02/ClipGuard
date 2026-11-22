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
        var action = _state.OnClipboardText(TryGetText());
        var verdict = _state.LastVerdict;
        switch (action)
        {
            case ClipboardAction.Quarantine:
                _restoreItem.Enabled = true;
                TryClear();
                Notify(ToolTipIcon.Error, "已攔截可疑的「貼上執行」指令",
                    "剪貼簿已清空。正常網站不會要你按 Win+R 貼上指令。\n" + string.Join("、", verdict.Reasons)
                    + "\n若確定安全，可從系統匣選單還原。");
                break;

            case ClipboardAction.WarnSuspicious:
                Notify(ToolTipIcon.Warning, "剪貼簿裡是會執行程式的指令",
                    "貼上前請確認來源可信。\n" + string.Join("、", verdict.Reasons));
                break;
        }
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

    private void Notify(ToolTipIcon icon, string title, string body) =>
        _tray.ShowBalloonTip(8000, title, body, icon);

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
