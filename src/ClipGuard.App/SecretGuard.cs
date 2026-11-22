using System.Security.Cryptography;
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

    /// <summary>有機密時回傳通知標題與內容（只含遮罩後的字串與標籤），沒有就回傳 null。</summary>
    public (string Title, string Body)? Check(string text)
    {
        var found = new List<SecretMatch>();
        if (_store is not null) found.AddRange(_store.Find(text));
        found.AddRange(SecretDetector.Find(text).Where(m =>
            !found.Any(r => m.Index < r.Index + r.Length && r.Index < m.Index + m.Length)));
        if (found.Count == 0) return null;

        var lines = found.Take(MaxListed).Select(m =>
            m.Kind == SecretKind.Registered ? m.Masked : $"{m.Label} {m.Masked}");
        var more = found.Count > MaxListed ? $"\n…另有 {found.Count - MaxListed} 筆" : "";

        return ("剪貼簿裡有機密資料",
            string.Join("\n", lines) + more + "\n貼上前請確認對象與網站可信。");
    }

    public void ShowRegisterDialog()
    {
        if (!EnsureStore()) return;
        using var dlg = new RegisterSecretForm();
        while (dlg.ShowDialog() == DialogResult.OK)
        {
            try
            {
                _store!.Add(dlg.SecretLabel, dlg.Secret);
                dlg.ClearSecret();
                MessageBox.Show("已登記。之後複製到這段文字時會提醒你。", "ClipGuard",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or IOException)
            {
                MessageBox.Show(ex.Message, "無法登記", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        dlg.ClearSecret();
    }

    public void ShowManageDialog()
    {
        if (!EnsureStore()) return;
        using var dlg = new ManageSecretsForm(_store!);
        dlg.ShowDialog();
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

/// <summary>登記機密：標籤 + 遮罩輸入 + 再輸入一次確認。</summary>
internal sealed class RegisterSecretForm : Form
{
    private readonly TextBox _label = new() { Width = 260, MaxLength = RegisteredSecretStore.MaxLabelLength, PlaceholderText = "例如：網銀密碼（會顯示在通知裡）" };
    private readonly TextBox _secret = new() { Width = 260, UseSystemPasswordChar = true };
    private readonly TextBox _confirm = new() { Width = 260, UseSystemPasswordChar = true };

    public string SecretLabel => _label.Text;
    public string Secret => _secret.Text;

    public RegisterSecretForm()
    {
        Text = "登記機密";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        TopMost = true;

        var ok = new Button { Text = "登記", DialogResult = DialogResult.None, AutoSize = true };
        var cancel = new Button { Text = "取消", DialogResult = DialogResult.Cancel, AutoSize = true };
        ok.Click += (_, _) => OnOk();
        AcceptButton = ok;
        CancelButton = cancel;

        var hint = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(380, 0),
            Text = $"只會保存長度與 HMAC，無法還原原文。長度需 {RegisteredSecretStore.MinLength}–{RegisteredSecretStore.MaxLength} 字元。",
        };

        var grid = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Padding = new Padding(12) };
        grid.Controls.Add(new Label { Text = "標籤", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 0);
        grid.Controls.Add(_label, 1, 0);
        grid.Controls.Add(new Label { Text = "機密", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 1);
        grid.Controls.Add(_secret, 1, 1);
        grid.Controls.Add(new Label { Text = "再輸入一次", AutoSize = true, Anchor = AnchorStyles.Left }, 0, 2);
        grid.Controls.Add(_confirm, 1, 2);
        grid.Controls.Add(hint, 0, 3);
        grid.SetColumnSpan(hint, 2);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        grid.Controls.Add(buttons, 0, 4);
        grid.SetColumnSpan(buttons, 2);

        Controls.Add(grid);
    }

    private void OnOk()
    {
        if (_secret.Text.Length == 0) { Warn("請輸入要登記的機密。"); return; }
        if (_secret.Text != _confirm.Text) { Warn("兩次輸入的內容不一樣。"); _confirm.Clear(); _confirm.Focus(); return; }
        DialogResult = DialogResult.OK;
    }

    private static void Warn(string message) =>
        MessageBox.Show(message, "登記機密", MessageBoxButtons.OK, MessageBoxIcon.Warning);

    public void ClearSecret()
    {
        _secret.Clear();
        _confirm.Clear();
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
