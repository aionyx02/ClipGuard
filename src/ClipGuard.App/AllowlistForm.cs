using System.Diagnostics;
using ClipGuard.Core;

namespace ClipGuard.App;

/// <summary>貼上攔截的允許清單：列出使用者加入的程式，可以新增（手打或從開著的視窗挑）和移除。</summary>
internal sealed class AllowlistForm : Form
{
    private readonly ListBox _list = new() { Width = 300, Height = 160 };
    private readonly ComboBox _input = new() { Width = 220, DropDownStyle = ComboBoxStyle.DropDown };

    public IReadOnlyList<string> AllowedApps => _list.Items.Cast<string>().ToList();

    public AllowlistForm(IEnumerable<string> current)
    {
        Text = "貼上攔截：允許清單";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        StartPosition = FormStartPosition.CenterScreen;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        TopMost = true;

        foreach (var a in current) _list.Items.Add(a);
        foreach (var name in RunningWindowedApps()) _input.Items.Add(name);

        var add = new Button { Text = "加入", AutoSize = true };
        var remove = new Button { Text = "移除選取的", AutoSize = true };
        var ok = new Button { Text = "儲存", AutoSize = true, DialogResult = DialogResult.OK };
        var cancel = new Button { Text = "取消", AutoSize = true, DialogResult = DialogResult.Cancel };
        add.Click += (_, _) => AddCurrent();
        remove.Click += (_, _) => { if (_list.SelectedIndex >= 0) _list.Items.RemoveAt(_list.SelectedIndex); };
        AcceptButton = ok;
        CancelButton = cancel;

        var intro = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(380, 0),
            Text = "在這些程式裡貼上機密時不會被攔截。填行程名稱（例如 Signal），可從下拉選單挑目前開著的程式。",
        };
        var builtIn = new Label
        {
            AutoSize = true,
            MaximumSize = new Size(380, 0),
            ForeColor = SystemColors.GrayText,
            Text = "內建放行：" + string.Join("、", PasteGuard.BuiltInAllowedApps) + "，以及 Windows 認證視窗和 ClipGuard 自己。",
        };

        var addRow = new FlowLayoutPanel { AutoSize = true };
        addRow.Controls.Add(_input);
        addRow.Controls.Add(add);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        buttons.Controls.Add(remove);

        var layout = new TableLayoutPanel { ColumnCount = 1, AutoSize = true, Padding = new Padding(12) };
        layout.Controls.Add(intro);
        layout.Controls.Add(addRow);
        layout.Controls.Add(_list);
        layout.Controls.Add(builtIn);
        layout.Controls.Add(buttons);
        Controls.Add(layout);
    }

    private void AddCurrent()
    {
        var name = PasteGuard.NormalizeAppName(_input.Text);
        if (name.Length is 0 or > PasteGuardSettingsStore.MaxAppNameLength) return;
        if (_list.Items.Count >= PasteGuardSettingsStore.MaxAllowedApps) return;
        if (!_list.Items.Cast<string>().Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase)))
            _list.Items.Add(name);
        _input.Text = "";
    }

    private static IEnumerable<string> RunningWindowedApps()
    {
        var names = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in Process.GetProcesses())
        {
            using (p)
            {
                try
                {
                    if (p.MainWindowHandle != IntPtr.Zero && p.Id != Environment.ProcessId) names.Add(p.ProcessName);
                }
                catch (InvalidOperationException) { }   // 行程剛結束
            }
        }
        return names;
    }
}
