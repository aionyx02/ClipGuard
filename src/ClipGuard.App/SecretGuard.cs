using System.Security.Cryptography;
using System.Windows.Forms.Automation;
using ClipGuard.Core;

namespace ClipGuard.App;

/// <summary>
/// 複製到機密時的提醒（格式偵測 + 使用者登記的機密），以及系統匣選單用的登記／管理視窗。
/// 獨立成一個檔案，讓 TrayApp 只需要接幾行。
/// </summary>
internal sealed class SecretGuard
{
    private const int MaxListed = 3;

    private RegisteredSecretStore? _store;
    private string? _storeError;
    // 個資的國家包（#27）：依 Windows 地區設定選，secret-packs.json 可以手動加或關。啟動時決定一次。
    private readonly IReadOnlySet<string> _packs = LoadPacks();

    private static IReadOnlySet<string> LoadPacks()
    {
        var manual = new SecretPackSettingsStore(RegisteredSecretStore.DefaultDirectory).Load(out _);
        return SecretPacks.ForRegion(System.Globalization.RegionInfo.CurrentRegion.TwoLetterISORegionName, manual.Extra, manual.Disabled);
    }

    public SecretGuard()
    {
        try
        {
            _store = new RegisteredSecretStore(RegisteredSecretStore.DefaultDirectory, new DpapiKeyProtector());
        }
        catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException
                                       or System.Text.Json.JsonException)
        {
            // 不把例外訊息以外的內容顯示出來；這裡也沒有任何剪貼簿資料。
            _storeError = ex.Message;
        }
    }

    /// <summary>有沒有登記任何機密；沒有的話，預設設定下貼上攔截不需要裝鍵盤 hook。</summary>
    public bool HasRegistered => _store is { Entries.Count: > 0 };

    /// <summary>登記的機密優先，偵測到的格式不能跟它重疊。結果只有遮罩字串與位置，不含原文。</summary>
    public IReadOnlyList<SecretMatch> Find(string text)
    {
        // 只跟登記的機密比重疊（筆數很少）；偵測結果本身已經互不重疊。
        // 不能拿正在變長的 found 來比，超長文字命中很多筆時會變成 O(n²)，卡住 UI。
        IReadOnlyList<SecretMatch> registered = _store is not null ? _store.Find(text) : [];
        var found = new List<SecretMatch>(registered);
        found.AddRange(SecretDetector.Find(text, _packs).Where(m =>
            !registered.Any(r => m.Index < r.Index + r.Length && r.Index < m.Index + m.Length)));
        found.Sort((a, b) => a.Index.CompareTo(b.Index));
        return found;
    }

    /// <summary>有機密時回傳通知標題與內容（只含遮罩後的字串與標籤），沒有就回傳 null。</summary>
    public static (string Title, string Body)? Describe(IReadOnlyList<SecretMatch> found)
    {
        if (found.Count == 0) return null;

        var lines = found.Take(MaxListed).Select(m =>
            m.Kind == SecretKind.Registered ? m.Masked : $"{m.Label} {m.Masked}");
        var more = found.Count > MaxListed ? $"\n…另有 {found.Count - MaxListed} 筆" : "";

        return ("剪貼簿裡有機密資料",
            string.Join("\n", lines) + more + "\n貼上前請確認對象與網站可信。");
    }

    public void ShowRegisterDialog(Action? changed = null)
    {
        if (!EnsureStore()) return;
        // 所有檢查（含寫入失敗、重複登記）都在對話框裡就地顯示，對話框只在登記成功或取消時才關。
        // 以前寫入失敗會先關掉對話框、跳一個沒有 owner 的訊息框再重開；那個訊息框可能落在別的視窗後面，
        // 看起來就像對話框自己消失了（#24 F19）。
        using var dlg = new RegisterSecretForm(TryAdd);
        var ok = dlg.ShowDialog() == DialogResult.OK;
        dlg.ClearSecret();
        if (ok) changed?.Invoke();
    }

    // 錯誤訊息只描述原因（長度、重複、無法寫檔），不含輸入的內容。成功回傳 null。
    private string? TryAdd(string label, string secret)
    {
        try
        {
            _store!.Add(label, secret);
            return null;
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException or UnauthorizedAccessException)
        {
            return ex.Message;
        }
    }

    public void ShowManageDialog(Action? changed = null)
    {
        if (!EnsureStore()) return;
        using var dlg = new ManageSecretsForm(_store!);
        dlg.ShowDialog();
        changed?.Invoke();
    }

    private bool EnsureStore()
    {
        if (_store is not null) return true;
        MessageBox.Show(
            "無法開啟已登記機密的金鑰（%LOCALAPPDATA%\\ClipGuard）。\n" +
            "可能是檔案損毀，或是從別的 Windows 帳號複製過來的。\n\n" + _storeError,
            "ClipGuard", MessageBoxButtons.OK, MessageBoxIcon.Error);
        return false;
    }
}

/// <summary>
/// 登記機密：標籤 + 遮罩輸入 + 再輸入一次確認。
///
/// 無障礙（#24 F19）：每個輸入框都有 AccessibleName，標籤的 TabIndex 緊接在輸入框前面、帶 Alt 快速鍵；
/// 輸入有問題時，錯誤顯示在欄位旁（ErrorProvider）和按鈕上方的紅字，同時寫進該欄的 AccessibleDescription
/// 並發出 UIA 通知，焦點留在出錯的欄位，螢幕報讀器會念出錯誤。
/// </summary>
internal sealed class RegisterSecretForm : Form
{
    private const string LabelDescription = "選填，會顯示在通知裡；留空會存成「未命名」。";
    private const string ConfirmDescription = "再輸入一次同樣的機密，確認沒有打錯。";
    private static readonly string SecretDescription =
        $"只會保存長度與 HMAC，無法還原原文。長度需 {RegisteredSecretStore.MinLength}–{RegisteredSecretStore.MaxLength} 字元。";

    private readonly Func<string, string, string?> _commit;
    private readonly TextBox _label = new() { Width = 260, MaxLength = RegisteredSecretStore.MaxLabelLength, PlaceholderText = "例如：網銀密碼（會顯示在通知裡）" };
    private readonly TextBox _secret = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly TextBox _confirm = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly Label _error = new()
    {
        AutoSize = true,
        MaximumSize = new Size(380, 0),
        ForeColor = Color.Firebrick,
        Visible = false,
        AccessibleRole = AccessibleRole.Alert,
        AccessibleName = "錯誤",
    };
    private readonly ErrorProvider _errors = new() { BlinkStyle = ErrorBlinkStyle.NeverBlink };

    public string SecretLabel => _label.Text;

    /// <param name="commit">真正寫入；失敗時回傳要顯示的錯誤訊息（例如重複登記），成功回傳 null。</param>
    public RegisterSecretForm(Func<string, string, string?> commit)
    {
        _commit = commit;
        Text = "登記機密";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        TopMost = true;

        _label.AccessibleName = "標籤";
        _label.AccessibleDescription = LabelDescription;
        _secret.AccessibleName = "機密";
        _secret.AccessibleDescription = SecretDescription;
        _confirm.AccessibleName = "再輸入一次機密";
        _confirm.AccessibleDescription = ConfirmDescription;

        // 輸入框右邊留空間給 ErrorProvider 的圖示，不然會被 AutoSize 的版面切掉。
        foreach (var box in new[] { _label, _secret, _confirm })
            box.Margin = new Padding(3, 3, 24, 3);
        _secret.TextChanged += (_, _) => ClearError(_secret);
        _confirm.TextChanged += (_, _) => ClearError(_confirm);

        // 「登記」不設 DialogResult：只有檢查和寫入都成功時，才在 OnOk 裡關閉。
        var ok = new Button { Text = "登記(&R)", AutoSize = true, TabIndex = 0 };
        var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, AutoSize = true, TabIndex = 1 };
        ok.Click += (_, _) => OnOk();
        AcceptButton = ok;
        CancelButton = cancel;

        var grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(12) };
        var tab = 0;
        void Row(int row, string caption, TextBox box)
        {
            // 標籤的 TabIndex 緊接在輸入框前面：Alt 快速鍵會跳到下一個可取得焦點的控制項，也就是這個輸入框；
            // 報讀器在沒有 AccessibleName 時也是用前一個標籤當名稱。
            grid.Controls.Add(new Label { Text = caption, AutoSize = true, Anchor = AnchorStyles.Left, TabIndex = tab++ }, 0, row);
            box.TabIndex = tab++;
            grid.Controls.Add(box, 1, row);
        }
        Row(0, "標籤(&L)", _label);
        Row(1, "機密(&S)", _secret);
        Row(2, "再輸入一次(&C)", _confirm);

        var hint = new Label { AutoSize = true, MaximumSize = new Size(380, 0), Text = SecretDescription, TabIndex = tab++ };
        grid.Controls.Add(hint, 0, 3);
        grid.SetColumnSpan(hint, 2);
        _error.TabIndex = tab++;
        grid.Controls.Add(_error, 0, 4);
        grid.SetColumnSpan(_error, 2);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, TabIndex = tab++ };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        grid.Controls.Add(buttons, 0, 5);
        grid.SetColumnSpan(buttons, 2);

        Controls.Add(grid);
        ActiveControl = _label;
    }

    private void OnOk()
    {
        if (SecretRegistration.Validate(_secret.Text, _confirm.Text) is { } invalid)
        {
            var field = invalid.Field switch
            {
                RegistrationField.Label => _label,
                RegistrationField.Confirm => _confirm,
                _ => _secret,
            };
            if (field == _confirm) _confirm.Clear();
            ShowError(field, invalid.Message);
            return;
        }

        if (_commit(_label.Text, _secret.Text) is { } failed)
        {
            ShowError(_secret, failed);
            return;
        }

        // 有 owner 的訊息框才會跟著置頂的對話框出現在最上層，不會落到別的視窗後面。
        MessageBox.Show(this, "已登記。之後複製到這段文字時會提醒你。", "ClipGuard",
            MessageBoxButtons.OK, MessageBoxIcon.Information);
        DialogResult = DialogResult.OK;
    }

    private void ShowError(TextBox field, string message)
    {
        ClearError(_secret);
        ClearError(_confirm);
        _errors.SetError(field, message);
        _error.Text = message;
        _error.AccessibleName = "錯誤：" + message;
        _error.Visible = true;
        field.AccessibleDescription = "錯誤：" + message;
        field.Focus();
        // 焦點本來就在這一欄時，報讀器不會重念；另外發一個通知讓它念出錯誤。
        field.AccessibilityObject.RaiseAutomationNotification(
            AutomationNotificationKind.Other, AutomationNotificationProcessing.ImportantMostRecent, message);
    }

    private void ClearError(TextBox field)
    {
        if (_errors.GetError(field).Length == 0) return;
        _errors.SetError(field, "");
        field.AccessibleDescription = field == _secret ? SecretDescription : ConfirmDescription;
        if (_errors.GetError(_secret).Length == 0 && _errors.GetError(_confirm).Length == 0)
            _error.Visible = false;
    }

    // 跟確認框一樣：沒按 Alt 的單一字母不觸發快速鍵（焦點在按鈕上時 WinForms 預設會），繼續打字不會誤按「登記」。
    protected override bool ProcessDialogChar(char charCode) =>
        (ModifierKeys & Keys.Alt) == 0 || base.ProcessDialogChar(charCode);

    protected override bool ProcessMnemonic(char charCode) =>
        (ModifierKeys & Keys.Alt) != 0 && base.ProcessMnemonic(charCode);

    public void ClearSecret()
    {
        _secret.Clear();
        _confirm.Clear();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _errors.Dispose();
        base.Dispose(disposing);
    }
}

/// <summary>列出已登記的機密（只有標籤、長度、日期）並可移除。</summary>
internal sealed class ManageSecretsForm : Form
{
    private readonly RegisteredSecretStore _store;
    private readonly ListView _list = new()
    {
        View = View.Details, FullRowSelect = true, MultiSelect = false, Width = 420, Height = 220,
    };

    public ManageSecretsForm(RegisteredSecretStore store)
    {
        _store = store;
        Text = "已登記的機密";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        TopMost = true;

        _list.Columns.Add("標籤", 200);
        _list.Columns.Add("長度", 60);
        _list.Columns.Add("登記時間", 140);

        var remove = new Button { Text = "移除", AutoSize = true };
        var close = new Button { Text = "關閉", DialogResult = DialogResult.Cancel, AutoSize = true };
        remove.Click += (_, _) => RemoveSelected();
        CancelButton = close;

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.Add(close);
        buttons.Controls.Add(remove);

        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Padding = new Padding(12) };
        layout.Controls.Add(_list);
        layout.Controls.Add(buttons);
        Controls.Add(layout);

        Reload();
    }

    private void Reload()
    {
        _list.Items.Clear();
        foreach (var e in _store.Entries)
        {
            // 原文本來就沒存，這裡只能、也只會顯示標籤與長度。
            var item = new ListViewItem([e.Label, $"{e.Length} 字", e.CreatedAt.LocalDateTime.ToString("yyyy-MM-dd HH:mm")])
            {
                Tag = e.Id,
            };
            _list.Items.Add(item);
        }
        if (_store.Entries.Count == 0)
            _list.Items.Add(new ListViewItem(["（尚未登記任何機密）", "", ""]));
    }

    private void RemoveSelected()
    {
        if (_list.SelectedItems.Count == 0 || _list.SelectedItems[0].Tag is not Guid id) return;
        var label = _list.SelectedItems[0].Text;
        if (MessageBox.Show($"確定移除「{label}」？", "已登記的機密", MessageBoxButtons.YesNo, MessageBoxIcon.Question)
            != DialogResult.Yes) return;
        try { _store.Remove(id); }
        catch (IOException ex) { MessageBox.Show(ex.Message, "無法移除", MessageBoxButtons.OK, MessageBoxIcon.Warning); }
        Reload();
    }
}
