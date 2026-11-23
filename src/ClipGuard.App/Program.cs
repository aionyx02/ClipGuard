namespace ClipGuard.App;

static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        // 介面語系（#27）：繁中 Windows 用 zh-TW，其他用英文；--lang=en／CLIPGUARD_LANG=zh-TW 可強制指定。
        // 要在建立任何視窗、讀任何字串之前設定。
        ClipGuard.Core.UiCulture.Apply(args);

        // 避免重複啟動，否則每次複製會收到多份通知。
        using var mutex = new Mutex(true, @"Local\ClipGuard.SingleInstance", out var isNew);
        if (!isNew) return;

        ApplicationConfiguration.Initialize();
        using var app = new TrayApp();
        Application.Run(app);
    }
}
