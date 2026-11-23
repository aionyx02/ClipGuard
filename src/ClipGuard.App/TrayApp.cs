using ClipGuard.Core;

namespace ClipGuard.App;

internal sealed class TrayApp : ApplicationContext
{
    private readonly NotifyIcon _tray;
    private readonly ClipboardMonitor _monitor;
    private readonly ToolStripMenuItem _restoreItem;
    private readonly ForegroundWatcher _foreground;
    private readonly EntryWarningGate _entryGate = new();
    private readonly SecretGuard _secrets = new();
    private readonly PasteInterceptor _paste;
    private readonly ToolStripMenuItem _strictRegisteredItem;
    private readonly ToolStripMenuItem _strictDetectedItem;
    // 上一次分析過的剪貼簿序號：貼上攔截可能先觸發一次分析，之後的 WM_CLIPBOARDUPDATE 不要再通知一次。
    private uint _analyzedSequence;

    // 判定、隔離與還原的狀態都在 Core；被清掉的內容只留在記憶體，不寫檔、不記 log。
    private readonly ClipboardGuardState _state = new();
    private readonly WalletSwapDetector _walletSwap = new();

    // 通知節流（#24 F18）：決策在 Core，這裡只負責顯示與計時。
    private readonly NotificationThrottle _throttle = new();
    private readonly System.Windows.Forms.Timer _notifyTimer = new();

    public TrayApp()
    {
        _restoreItem = new ToolStripMenuItem("還原被清除的內容", null, (_, _) => Restore()) { Enabled = false };

        _paste = new PasteInterceptor(_secrets, RegisteredSecretStore.DefaultDirectory,
            reanalyzeClipboard: () => OnClipboardChanged(null, EventArgs.Empty),
            notify: (title, body) => Notify(ToolTipIcon.Warning, title, body));

        _strictRegisteredItem = new ToolStripMenuItem("攔截已登記的機密", null,
            (_, _) => UpdatePasteSettings(s => s with { InterceptRegistered = !s.InterceptRegistered }));
        _strictDetectedItem = new ToolStripMenuItem("也攔截個資與 API key", null,
            (_, _) => UpdatePasteSettings(s => s with { InterceptDetected = !s.InterceptDetected }));
        var pasteMenu = new ToolStripMenuItem("貼上前確認（嚴格模式）");
        pasteMenu.DropDownItems.Add(_strictRegisteredItem);
        pasteMenu.DropDownItems.Add(_strictDetectedItem);
        pasteMenu.DropDownItems.Add(new ToolStripSeparator());
        pasteMenu.DropDownItems.Add("允許清單…", null, (_, _) => ShowAllowlist());
        SyncPasteMenu();

        var menu = new ContextMenuStrip();
        menu.Items.Add(_restoreItem);
        menu.Items.Add("登記機密…", null, (_, _) => _secrets.ShowRegisterDialog(_paste.RefreshHook));
        menu.Items.Add("管理已登記的機密…", null, (_, _) => _secrets.ShowManageDialog(_paste.RefreshHook));
        menu.Items.Add(pasteMenu);
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("結束", null, (_, _) => ExitThread());

        _tray = new NotifyIcon
        {
            Icon = LoadAppIcon(),
            Text = "ClipGuard：剪貼簿防護中",
            ContextMenuStrip = menu,
            Visible = true,
        };

        // 不在 BalloonTipClosed 清掉：撤掉舊通知（ReplaceVisible）時，舊通知的關閉訊息可能晚於新通知才到，
        // 會把新的「點擊還原」清掉。點擊動作每次顯示都會覆蓋，而且 Restore 自己會檢查還有沒有可還原的內容。
        _tray.BalloonTipClicked += (_, _) => { var a = _balloonClick; _balloonClick = null; a?.Invoke(); };
        _notifyTimer.Tick += (_, _) => { _notifyTimer.Stop(); Apply(_throttle.Flush()); };

        _monitor = new ClipboardMonitor();
        _monitor.ClipboardChanged += OnClipboardChanged;

        _foreground = new ForegroundWatcher();
        _foreground.ForegroundChanged += OnForegroundChanged;

        // 啟動前（或啟動途中）就已複製的內容不會觸發通知，等訊息迴圈開始後先檢查一次。
        var startup = new System.Windows.Forms.Timer { Interval = 1 };
        startup.Tick += (_, _) =>
        {
            startup.Dispose();
            OnClipboardChanged(null, EventArgs.Empty);
            if (_paste.SettingsError is not null || _paste.HookError is not null)
                Notify(ToolTipIcon.Warning, "貼上前確認的設定有問題", _paste.HookError ?? "設定檔損毀，已改用預設值。");
        };
        startup.Start();
    }

    // 系統匣用嵌入的品牌圖示；讀不到時退回系統的盾牌圖示，不讓啟動失敗。
    private static Icon LoadAppIcon()
    {
        using var stream = typeof(TrayApp).Assembly.GetManifestResourceStream("ClipGuard.App.clipguard.ico");
        return stream is null ? SystemIcons.Shield : new Icon(stream, SystemInformation.SmallIconSize);
    }

    private void OnClipboardChanged(object? sender, EventArgs e)
    {
        // 只讀前 MaxAnalyzedChars 字（#24 F20）：超大內容不會把整段讀進記憶體好幾份。
        var read = ClipboardAccess.TryGetTextPrefix();
        var text = read?.Text;
        // 讀完才取序號：延遲產生格式的程式在被讀取時才寫入，先取的話摘要會一出生就過期。
        var sequence = ClipboardAccess.SequenceNumber;
        if (sequence == _analyzedSequence && sender is not null) return;
        if (sequence != _analyzedSequence) _throttle.OnClipboardChanged();   // 還沒顯示的舊通知作廢
        _analyzedSequence = sequence;

        // 截斷過的內容要被清空時，隔離區存完整的原文，還原才不會少一截。
        var action = _state.OnClipboardText(text, read is { Truncated: true } ? ClipboardAccess.TryGetText : null);

        // 貼上攔截只記「有哪些機密」的摘要（種類＋遮罩），不記原文。被清空的指令不算。
        var secrets = text is not null && action != ClipboardAction.Quarantine ? _secrets.Find(text) : [];
        _paste.UpdateSnapshot(ClipboardSecretSnapshot.From(sequence, secrets));

        // 貼遮罩版時自己暫時寫入的遮罩版、事後還原的原文：複製當下已經通知過，不再跳一次。
        if (text is not null && action != ClipboardAction.Quarantine && _paste.IsSelfWrite(text)) return;

        // 白話說明與解碼內容只放進通知，不寫檔、不記 log。只有需要通知時才產生。
        var explanation = action is ClipboardAction.Quarantine or ClipboardAction.WarnSuspicious && text is not null
            ? CommandExplainer.Explain(text)
            : null;

        // 錢包掉包每次都要記錄（記住最後一次看到的地址）；通知只讓給「指令被攔截」（§2）。
        var swap = _walletSwap.Observe(text, UserInput.IdleTime());

        var secretNotified = false;
        switch (action)
        {
            case ClipboardAction.Quarantine:
                _restoreItem.Enabled = true;
                TryClear();
                Notify(ToolTipIcon.Error, "已攔截可疑的「貼上執行」指令",
                    ComposeBody("剪貼簿已清空，正常網站不會要你按 Win+R 貼上指令。", explanation!,
                        "若確定安全，點這則通知或從系統匣選單還原。"),
                    restorable: true);
                break;

            case ClipboardAction.WarnSuspicious when swap is null:
                Notify(ToolTipIcon.Warning, "剪貼簿裡是會執行程式的指令",
                    ComposeBody("貼上前請確認來源可信。", explanation!, null));
                break;

            // 不是指令才檢查機密，避免蓋掉上面更重要的通知；通知內容只有遮罩後的字串與標籤。
            case ClipboardAction.None when swap is null && SecretGuard.Describe(secrets) is { } secret:
                Notify(ToolTipIcon.Warning, secret.Title, secret.Body);
                secretNotified = true;
                break;
        }

        // 指令警告優先：已經跳出攔截或提醒時，不再用隱藏字元通知蓋掉它（攔截通知帶有「點擊還原」）。
        if (swap is not null && action != ClipboardAction.Quarantine)
            NotifyWalletSwap(swap);
        else if (text is not null)
            CheckHiddenChars(text, notifyHiddenChars: action == ClipboardAction.None && !secretNotified);
    }

    // 錢包地址掉包（#6、#23）。通知不顯示地址，連遮罩版都不顯示（P4）。
    private void NotifyWalletSwap(WalletSwap swap)
    {
        var to = swap.ReplacementCurrency == swap.Currency ? "" : $" {swap.ReplacementCurrency} ";
        Notify(ToolTipIcon.Error, "錢包地址可能被掉包",
            $"剛複製的 {swap.Currency} 地址在 {swap.Elapsed.TotalMilliseconds:0} 毫秒後被換成另一個{to}地址，可能有剪貼簿劫持惡意程式。\n"
            + "請勿貼上；假地址常與原地址頭尾相同，請逐字核對並掃毒。");
    }

    // 隱藏字元（#5、#23）。通知只顯示 code point，不顯示原文。
    private void CheckHiddenChars(string text, bool notifyHiddenChars)
    {
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

    // 點通知時要做的事（還原）；每則新通知都會覆蓋。
    private Action? _balloonClick;

    private void Notify(ToolTipIcon icon, string title, string body, bool restorable = false)
    {
        var level = icon == ToolTipIcon.Error ? NotificationLevel.Error : NotificationLevel.Warning;
        Apply(_throttle.Submit(new TrayNotification(level, title, body, restorable)));
    }

    private void Apply(NotificationDecision decision)
    {
        if (decision.RetryIn is { } wait)
        {
            _notifyTimer.Stop();
            _notifyTimer.Interval = (int)Math.Clamp(Math.Ceiling(wait.TotalMilliseconds), 1, int.MaxValue);
            _notifyTimer.Start();
        }
        if (decision.Show is not { } n) return;
        if (_throttle.Pending is null) _notifyTimer.Stop();

        // 上一則可能還在畫面上或在 Windows 的佇列裡：移除再加回圖示會把它撤掉，新的才不會排在後面。
        if (decision.ReplaceVisible)
        {
            _tray.Visible = false;
            _tray.Visible = true;
        }

        _balloonClick = n.Restorable ? Restore : null;
        var title = n.Title.Length > 63 ? n.Title[..62] + "…" : n.Title;   // szInfoTitle 上限
        var body = n.Body.Length > MaxBodyLength ? n.Body[..(MaxBodyLength - 1)] + "…" : n.Body;
        _tray.ShowBalloonTip(8000, title, body, n.Level == NotificationLevel.Error ? ToolTipIcon.Error : ToolTipIcon.Warning);
    }

    private void UpdatePasteSettings(Func<PasteGuardSettings, PasteGuardSettings> change)
    {
        try
        {
            _paste.UpdateSettings(change(_paste.Settings));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "無法儲存設定", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
        SyncPasteMenu();
        if (_paste.HookError is not null) Notify(ToolTipIcon.Warning, "貼上前確認沒有作用", _paste.HookError);
    }

    private void SyncPasteMenu()
    {
        _strictRegisteredItem.Checked = _paste.Settings.InterceptRegistered;
        _strictDetectedItem.Checked = _paste.Settings.InterceptDetected;
    }

    private void ShowAllowlist()
    {
        using var dlg = new AllowlistForm(_paste.Settings.AllowedApps);
        if (dlg.ShowDialog() == DialogResult.OK)
            UpdatePasteSettings(s => s with { AllowedApps = dlg.AllowedApps });
    }

    private static void TryClear() => ClipboardAccess.TryClear();

    private static bool TrySetText(string text) => ClipboardAccess.TrySetText(text);

    protected override void ExitThreadCore()
    {
        // 先拔掉鍵盤 hook，再結束訊息迴圈：回呼要靠這個迴圈才跑得動，迴圈停了還掛著會拖慢全系統的按鍵。
        _paste.Dispose();
        base.ExitThreadCore();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _paste.Dispose();
            _notifyTimer.Dispose();
            _foreground.Dispose();
            _monitor.Dispose();
            _tray.Visible = false;
            _tray.Dispose();
        }
        base.Dispose(disposing);
    }
}
