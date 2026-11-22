namespace ClipGuard.App;

static class Program
{
    [STAThread]
    static void Main()
    {
        // 避免重複啟動，否則每次複製會收到多份通知。
        using var mutex = new Mutex(true, @"Local\ClipGuard.SingleInstance", out var isNew);
        if (!isNew) return;

        ApplicationConfiguration.Initialize();
        Application.Run(new TrayApp());
    }
}
