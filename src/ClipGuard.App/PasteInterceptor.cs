using ClipGuard.Core;

namespace ClipGuard.App;

/// <summary>
/// 貼上攔截（嚴格模式，#25）：剪貼簿含機密時，在 Ctrl+V／Shift+Insert 按下的當下擋住，先問使用者。
///
/// 流程：
///   複製 → TrayApp 分析後呼叫 <see cref="UpdateSnapshot"/>，這裡只記「種類＋遮罩＋剪貼簿序號」
///   按下貼上 → hook 回呼（要快）：查前景視窗 → <see cref="PasteGuard.Decide"/> → 要攔就吞掉按鍵，BeginInvoke 跳確認框
///   確認框 → 取消／貼遮罩版／貼原文 → 切回原視窗 → 必要時暫換剪貼簿 → 送出帶標記的貼上 → 換回原內容
///
/// 重入處理：
///   - 自己送的按鍵帶 <see cref="KeyboardPasteHook.InjectedMarker"/>，hook 直接放行。
///   - 自己寫進剪貼簿的內容（遮罩版、還原的原文）登記在 <see cref="IsSelfWrite"/>，TrayApp 收到時不跳通知。
/// </summary>
internal sealed class PasteInterceptor : IDisposable
{
    // 送出貼上後等多久才把剪貼簿換回原文。目標程式是在處理 WM_KEYDOWN 時才去讀剪貼簿，沒有完成通知可等。
    private const int RestoreDelayMs = 600;
    // 自己寫入的內容在這段時間內出現在剪貼簿，都當成自己的寫入（一次寫入可能觸發多次 WM_CLIPBOARDUPDATE）。
    private const int SelfWriteWindowMs = 3000;

    private readonly SecretGuard _secrets;
    private readonly PasteGuardSettingsStore _store;
    private readonly KeyboardPasteHook _hook = new();
    private readonly SynchronizationContext _ui;
    private readonly Action _reanalyzeClipboard;
    private readonly Action<string, string> _notify;

    private ClipboardSecretSnapshot _snapshot = ClipboardSecretSnapshot.Empty(0);
    // 已經吞掉一次貼上、使用者還沒在確認框做決定。期間送往原目標視窗的 Enter 先擋住。
    // 最多等 PasteGuard.PendingTimeout，確認框也會在那時自動取消，所以不會一直卡著。
    private bool _pending;
    private long _pendingSince;
    private IntPtr _pendingTargetRoot;
    private PasteConfirmForm? _dialog;

    private readonly List<(string Text, long Until)> _selfWrites = [];

    public PasteGuardSettings Settings { get; private set; }
    public string? SettingsError { get; }
    public string? HookError { get; private set; }

    public PasteInterceptor(SecretGuard secrets, string directory, Action reanalyzeClipboard, Action<string, string> notify)
    {
        _secrets = secrets;
        _store = new PasteGuardSettingsStore(directory);
        // 明確建立 WinForms 的 context：TrayApp 建構時 Application.Run 還沒開始，Current 可能是會丟到執行緒集區的預設 context，
        // 那樣確認框會跑在 MTA 執行緒上，剪貼簿也讀不到。
        _ui = new WindowsFormsSynchronizationContext();
        _reanalyzeClipboard = reanalyzeClipboard;
        _notify = notify;
        Settings = _store.Load(out var error);
        SettingsError = error;

        _hook.PastePressed = OnPastePressed;
        _hook.EnterPressed = OnEnterPressed;
        RefreshHook();
    }

    public void UpdateSettings(PasteGuardSettings settings)
    {
        _store.Save(settings);
        Settings = settings;
        RefreshHook();
    }

    /// <summary>只有設定有可能攔截時才裝 hook：沒有登記機密、也沒開個資攔截的使用者完全不受影響。</summary>
    public void RefreshHook()
    {
        if (Settings.CanIntercept(_secrets.HasRegistered))
        {
            var err = _hook.Install();
            HookError = err == 0 ? null : $"無法安裝鍵盤 hook（錯誤 {err}），貼上攔截沒有作用。";
        }
        else
        {
            _hook.Uninstall();
            HookError = null;
        }
    }

    public bool HookInstalled => _hook.Installed;

    public void UpdateSnapshot(ClipboardSecretSnapshot snapshot) => _snapshot = snapshot;

    public bool IsSelfWrite(string text)
    {
        var now = Environment.TickCount64;
        _selfWrites.RemoveAll(w => w.Until < now);
        return _selfWrites.Any(w => w.Text == text);
    }

    private void MarkSelfWrite(string text) =>
        _selfWrites.Add((text, Environment.TickCount64 + SelfWriteWindowMs));

    // ---------------------------------------------------------------- hook 回呼（要快、不能丟例外）

    private TimeSpan PendingFor => TimeSpan.FromMilliseconds(Environment.TickCount64 - _pendingSince);

    // 逾時還沒清掉（理論上不會發生）就當作沒在等，避免任何狀況讓攔截一直卡住。
    private bool IsPending => _pending && PendingFor < PasteGuard.PendingTimeout;

    private void BeginPending(IntPtr foreground)
    {
        _pending = true;
        _pendingSince = Environment.TickCount64;
        _pendingTargetRoot = WindowFocus.Root(foreground);
    }

    private void EndPending()
    {
        _pending = false;
        _pendingTargetRoot = IntPtr.Zero;
    }

    private bool OnPastePressed(IntPtr foreground, PasteChord chord)
    {
        if (WindowFocus.IsOwnWindow(foreground)) return false;   // 確認框、登記視窗裡照常貼上

        var target = WindowFocus.Describe(foreground);
        if (PasteGuard.IsAllowed(target, Settings)) return false;
        var pending = IsPending;

        if (ClipboardAccess.SequenceNumber != _snapshot.Sequence)
        {
            // 剪貼簿剛換過、WM_CLIPBOARDUPDATE 還沒處理（複製後立刻貼上）。不知道新內容有沒有機密，
            // 先擋下來，分析完再決定要跳確認框還是照原樣把貼上送回去。已經有確認框在等時就照常放行，
            // 只有一個確認框，不能為了它擋住其他程式的一般貼上。
            if (pending) return false;
            BeginPending(foreground);
            _ui.Post(_ => HandleStalePaste(foreground, chord, target), null);
            return true;
        }

        if (PasteGuard.Decide(_snapshot.Kinds, target, Settings) == PasteDecision.Allow) return false;

        // 已經有一個確認框在等：這次一樣是機密，擋下但不再開第二個確認框。
        if (pending) return true;

        BeginPending(foreground);
        _ui.Post(_ => ConfirmAndPaste(foreground, chord, target), null);
        return true;
    }

    private bool OnEnterPressed(IntPtr foreground) =>
        // 確認框還沒搶到焦點（或使用者點走了）時，Enter 不能送到原本要貼上的那個程式；其他程式照常。
        PasteGuard.ShouldSwallowEnter(_pending, PendingFor, WindowFocus.Root(foreground), _pendingTargetRoot,
            WindowFocus.IsOwnWindow(foreground));

    // ---------------------------------------------------------------- UI 執行緒

    private async void HandleStalePaste(IntPtr target, PasteChord chord, PasteTarget info)
    {
        try
        {
            _reanalyzeClipboard();
            if (PasteGuard.Decide(_snapshot.Kinds, info, Settings) == PasteDecision.Intercept)
            {
                ConfirmAndPaste(target, chord, info);
                return;
            }
            EndPending();
            if (await WindowFocus.ActivateAsync(target)) KeyboardPasteHook.SendPaste(chord);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            EndPending();
        }
    }

    private async void ConfirmAndPaste(IntPtr target, PasteChord chord, PasteTarget info)
    {
        PasteChoice choice;
        // 使用者沒注意到確認框時，逾時自動取消（結果 = Cancel，焦點切回目標），等待狀態不會一直卡著。
        var remaining = PasteGuard.PendingTimeout - PendingFor;
        using var timeout = new System.Windows.Forms.Timer { Interval = (int)Math.Max(1, remaining.TotalMilliseconds) };
        try
        {
            using var dlg = new PasteConfirmForm(_snapshot.Secrets, info.ProcessName);
            _dialog = dlg;
            timeout.Tick += (_, _) => { timeout.Stop(); dlg.Close(); };
            timeout.Start();
            dlg.ShowDialog();
            choice = dlg.Choice;
        }
        finally
        {
            timeout.Stop();
            _dialog = null;
            EndPending();
        }

        try
        {
            switch (choice)
            {
                case PasteChoice.Cancel:
                    await WindowFocus.ActivateAsync(target);
                    break;
                case PasteChoice.Original:
                    if (await WindowFocus.ActivateAsync(target)) KeyboardPasteHook.SendPaste(chord);
                    else _notify("沒有貼上", "無法切回原本的視窗，請自己再貼一次。");
                    break;
                case PasteChoice.Masked:
                    await PasteMaskedAsync(target, chord);
                    break;
            }
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // 不顯示例外內容：理論上不含剪貼簿資料，但沒必要冒險。
            _notify("貼上時發生錯誤", "剪貼簿可能還是遮罩版，請重新複製一次。");
        }
    }

    /// <summary>暫時把剪貼簿換成遮罩版 → 對原視窗送出貼上 → 換回原內容。</summary>
    private async Task PasteMaskedAsync(IntPtr target, PasteChord chord)
    {
        var text = ClipboardAccess.TryGetText();
        var saved = ClipboardAccess.TrySaveTextFormats();
        if (text is null || saved is null)
        {
            _notify("沒有貼上", "讀不到剪貼簿內容，請重新複製一次。");
            return;
        }

        var masked = PasteGuard.MaskText(text, _secrets.Find(text));
        if (!await WindowFocus.ActivateAsync(target))
        {
            _notify("沒有貼上", "無法切回原本的視窗，剪貼簿沒有變動。");
            return;
        }

        MarkSelfWrite(masked);
        if (!ClipboardAccess.TrySetTextExcludedFromHistory(masked))
        {
            _notify("沒有貼上", "無法寫入剪貼簿，請稍後再試。");
            return;
        }
        var maskedSeq = ClipboardAccess.SequenceNumber;

        // 寫剪貼簿會讓我們短暫取得焦點的情況很少見，但送按鍵前再確認一次目標還在前景。
        var sent = (WindowFocus.GetForegroundWindow() == target || await WindowFocus.ActivateAsync(target, 300))
                   && KeyboardPasteHook.SendPaste(chord);
        if (sent) await Task.Delay(RestoreDelayMs);
        else _notify("沒有貼上", "無法把貼上送回原本的視窗。");

        // 這段時間使用者又複製了別的東西：不要用舊內容蓋掉。
        if (ClipboardAccess.SequenceNumber != maskedSeq) return;
        MarkSelfWrite(text);
        if (!ClipboardAccess.TrySet(saved))
            _notify("剪貼簿還是遮罩版", "無法換回原本的內容，需要的話請重新複製一次。");
    }

    public void Dispose()
    {
        _hook.Dispose();
        _dialog?.Close();
    }
}
