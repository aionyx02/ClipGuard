using ClipGuard.Core;

namespace ClipGuard.App;

internal enum PasteChoice
{
    Cancel,
    Masked,
    Original,
}

/// <summary>
/// 貼上攔截的確認框。置頂並搶焦點，讓使用者手快按下的 Enter 落在這裡，而不是聊天程式的「送出」。
///
/// - Enter 和 Esc 都是「取消」：誤按時什麼都不會貼上，剪貼簿也不會被動到。
/// - 「貼上遮罩版」可以用 Tab 移過去或 Alt+M。
/// - 「貼上原文」只能用滑鼠點或 Alt+O：不在 Tab 順序裡，Enter 永遠按不到它。
/// - 不按 Alt 的單一字母不會觸發按鈕（WinForms 對話框預設會），使用者繼續打字也不會誤選。
/// </summary>
internal sealed class PasteConfirmForm : Form
{
    private const int MaxListed = 3;

    public PasteChoice Choice { get; private set; } = PasteChoice.Cancel;

    public PasteConfirmForm(IReadOnlyList<SecretSummary> secrets, string targetName)
    {
        Text = Strings.Confirm_Title;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = true;   // 沒搶到焦點時，使用者還能從工作列找到它
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        TopMost = true;
        KeyPreview = false;

        var lines = secrets.Take(MaxListed).Select(s => s.Kind == SecretKind.Registered ? s.Masked : $"{s.Label} {s.Masked}").ToList();
        if (secrets.Count > MaxListed) lines.Add(Strings.Secret_More(secrets.Count - MaxListed));

        var head = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(420, 0),
            Font = new Font(Font, FontStyle.Bold),
            Text = targetName.Length > 0 ? Strings.Confirm_HeadWithTarget(targetName) : Strings.Confirm_Head,
        };
        var list = new Label { AutoSize = true, MaximumSize = new Size(420, 0), Text = string.Join("\n", lines) };
        var hint = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(420, 0),
            ForeColor = SystemColors.GrayText,
            Text = Strings.Confirm_Hint,
        };

        var cancel = new Button { Text = Strings.Common_Cancel, AutoSize = true, DialogResult = DialogResult.Cancel };
        var masked = new Button { Text = Strings.Confirm_PasteMasked, AutoSize = true };
        var original = new Button { Text = Strings.Confirm_PasteOriginal, AutoSize = true, TabStop = false };
        masked.Click += (_, _) => Close(PasteChoice.Masked);
        original.Click += (_, _) => Close(PasteChoice.Original);
        AcceptButton = cancel;
        CancelButton = cancel;

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(masked);
        buttons.Controls.Add(original);

        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Padding = new Padding(12) };
        layout.Controls.Add(head);
        layout.Controls.Add(list);
        layout.Controls.Add(hint);
        layout.Controls.Add(buttons);
        Controls.Add(layout);

        ActiveControl = cancel;
    }

    private void Close(PasteChoice choice)
    {
        Choice = choice;
        DialogResult = DialogResult.OK;
    }

    // 預設 WinForms 會讓沒按 Alt 的字母直接觸發按鈕（焦點在按鈕上時），使用者還在打字就可能誤選。
    protected override bool ProcessDialogChar(char charCode) =>
        (ModifierKeys & Keys.Alt) == 0 || base.ProcessDialogChar(charCode);

    protected override bool ProcessMnemonic(char charCode) =>
        (ModifierKeys & Keys.Alt) != 0 && base.ProcessMnemonic(charCode);

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        WindowFocus.ForceForeground(Handle);
        Activate();
    }
}
