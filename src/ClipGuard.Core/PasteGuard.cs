namespace ClipGuard.Core;

public enum PasteDecision
{
    /// <summary>照常貼上，不介入。</summary>
    Allow,
    /// <summary>吞掉這次貼上，先問使用者。</summary>
    Intercept,
}

/// <summary>
/// 貼上攔截（嚴格模式）的設定。不含任何機密或剪貼簿內容，只有開關與程式名稱。
/// </summary>
public sealed record PasteGuardSettings
{
    public static PasteGuardSettings Default { get; } = new();

    /// <summary>剪貼簿含「登記的機密」時攔截貼上。預設開：使用者主動登記的才是高價值機密。</summary>
    public bool InterceptRegistered { get; init; } = true;

    /// <summary>剪貼簿含偵測到的個資或 API key 時也攔截。預設關，避免每次貼上電話都要確認。</summary>
    public bool InterceptDetected { get; init; }

    /// <summary>使用者加入允許清單的程式（行程名稱，不分大小寫，可帶 .exe）。</summary>
    public IReadOnlyList<string> AllowedApps { get; init; } = [];

    /// <summary>目前的設定有沒有可能攔截任何東西；不可能時 App 不必裝鍵盤 hook。</summary>
    public bool CanIntercept(bool hasRegisteredSecrets) =>
        InterceptDetected || (InterceptRegistered && hasRegisteredSecrets);
}

/// <summary>貼上的目標：前景視窗所屬的行程名稱與視窗 class。</summary>
/// <param name="ProcessName">行程名稱，例如 <c>Discord</c>（有沒有 .exe 都可以）。</param>
/// <param name="WindowClass">前景視窗的 class name。</param>
/// <param name="IsOwnProcess">目標是 ClipGuard 自己的視窗（確認框、登記機密視窗等），一律放行。</param>
public sealed record PasteTarget(string ProcessName, string WindowClass, bool IsOwnProcess = false);

/// <summary>
/// 「這份剪貼簿含機密」的摘要。只記種類、標籤、遮罩字串和剪貼簿序號，不記原文；
/// 要貼遮罩版時，App 會重新讀剪貼簿（原文本來就在剪貼簿裡）再遮罩。
/// </summary>
/// <param name="Sequence">建立摘要時的剪貼簿序號（Win32 GetClipboardSequenceNumber），用來判斷摘要是否過期。</param>
public sealed record ClipboardSecretSnapshot(uint Sequence, IReadOnlyList<SecretSummary> Secrets)
{
    public static ClipboardSecretSnapshot Empty(uint sequence) => new(sequence, []);

    public static ClipboardSecretSnapshot From(uint sequence, IEnumerable<SecretMatch> matches) =>
        new(sequence, matches.Select(m => new SecretSummary(m.Kind, m.Label, m.Masked)).ToList());

    public IReadOnlyCollection<SecretKind> Kinds => Secrets.Select(s => s.Kind).Distinct().ToList();
}

/// <summary>一筆機密的摘要：沒有位置、沒有原文。</summary>
public sealed record SecretSummary(SecretKind Kind, string Label, string Masked);

/// <summary>
/// 貼上當下要不要攔截。純邏輯：App 的鍵盤 hook 收到 Ctrl+V／Shift+Insert 時呼叫。
/// </summary>
public static class PasteGuard
{
    /// <summary>
    /// 內建允許清單：密碼管理器本來就是拿來貼密碼的；Windows 的認證視窗（UAC、網路認證、
    /// Windows Hello 備援）也是。比對行程名稱，不分大小寫。
    /// </summary>
    public static IReadOnlyList<string> BuiltInAllowedApps { get; } =
    [
        "1Password", "KeePass", "KeePassXC", "Bitwarden", "Dashlane", "Enpass", "Keeper",
        "RoboForm", "NordPass", "ProtonPass", "LastPass", "CredentialUIBroker", "consent",
    ];

    /// <summary>Windows 認證對話框（CredUI）的視窗 class，不管由哪個行程開出來都放行。</summary>
    public static IReadOnlyList<string> BuiltInAllowedWindowClasses { get; } =
    [
        "Credential Dialog Xaml Host",
    ];

    public static PasteDecision Decide(IReadOnlyCollection<SecretKind> kinds, PasteTarget target, PasteGuardSettings settings)
    {
        ArgumentNullException.ThrowIfNull(kinds);
        ArgumentNullException.ThrowIfNull(target);
        ArgumentNullException.ThrowIfNull(settings);

        if (kinds.Count == 0 || target.IsOwnProcess) return PasteDecision.Allow;

        var applies = (settings.InterceptRegistered && kinds.Contains(SecretKind.Registered))
                      || (settings.InterceptDetected && kinds.Any(k => k != SecretKind.Registered));
        if (!applies) return PasteDecision.Allow;

        if (IsAllowed(target, settings)) return PasteDecision.Allow;
        return PasteDecision.Intercept;
    }

    public static bool IsAllowed(PasteTarget target, PasteGuardSettings settings)
    {
        if (target.IsOwnProcess) return true;
        if (BuiltInAllowedWindowClasses.Contains(target.WindowClass, StringComparer.Ordinal)) return true;
        var name = NormalizeAppName(target.ProcessName);
        if (name.Length == 0) return false;   // 查不到行程名稱時不能假設它在清單裡
        return BuiltInAllowedApps.Concat(settings.AllowedApps)
            .Any(a => string.Equals(NormalizeAppName(a), name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>去掉空白、路徑和 .exe，讓「Signal.exe」「C:\…\signal.exe」「Signal」都視為同一個。</summary>
    public static string NormalizeAppName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "";
        var n = name.Trim();
        var slash = n.LastIndexOfAny(['\\', '/']);
        if (slash >= 0) n = n[(slash + 1)..];
        if (n.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) n = n[..^4];
        return n.Trim();
    }

    /// <summary>
    /// 把文字裡每一筆機密換成遮罩字串（給「貼上遮罩版」用）。登記的機密換成固定的星號，
    /// 不帶標籤也不洩漏長度。<paramref name="matches"/> 必須是對同一份 <paramref name="text"/> 找出來的。
    /// </summary>
    public static string MaskText(string text, IEnumerable<SecretMatch> matches)
    {
        ArgumentNullException.ThrowIfNull(text);
        var sb = new System.Text.StringBuilder(text.Length);
        var pos = 0;
        foreach (var m in matches.OrderBy(m => m.Index))
        {
            if (m.Index < pos || m.Index + m.Length > text.Length) continue;   // 重疊或越界：略過
            sb.Append(text, pos, m.Index - pos);
            pos = m.Index + m.Length;
            if (m.Kind == SecretKind.Registered)
            {
                sb.Append(RegisteredMask);
            }
            else if (IsPemHeader(m))
            {
                // PEM 只比對到標頭，真正的機密在標頭後面：一路遮到 END 行（沒有 END 就遮到結尾）。
                sb.Append(m.Masked).Append('\n').Append(PemBodyMask).Append('\n');
                var end = text.IndexOf("-----END ", pos, StringComparison.Ordinal);
                pos = end < 0 ? text.Length : end;
            }
            else
            {
                sb.Append(m.Masked);
            }
        }
        sb.Append(text, pos, text.Length - pos);
        return sb.ToString();
    }

    /// <summary>
    /// 攔下一次貼上之後，最多等使用者多久；超過就當成取消，保證「等待中」不會卡住。
    /// </summary>
    public static readonly TimeSpan PendingTimeout = TimeSpan.FromSeconds(60);

    /// <summary>
    /// 已攔下貼上、使用者還沒決定時，這次 Enter 要不要吞掉。
    /// 只擋送往「原本要貼上的那個視窗」的 Enter（防止在確認框搶到焦點前按下聊天程式的送出）；
    /// 其他程式的 Enter 一律放行，使用者沒注意到確認框也不會整台電腦的 Enter 都失靈。
    /// </summary>
    /// <param name="pending">是否正在等使用者決定。</param>
    /// <param name="pendingFor">已經等了多久；超過 <see cref="PendingTimeout"/> 就不再擋。</param>
    /// <param name="foregroundRoot">目前前景視窗的最上層視窗（GetAncestor GA_ROOT）。</param>
    /// <param name="targetRoot">被攔下的那次貼上的目標最上層視窗。</param>
    /// <param name="foregroundIsOwn">前景是 ClipGuard 自己的視窗（確認框）。</param>
    public static bool ShouldSwallowEnter(bool pending, TimeSpan pendingFor, nint foregroundRoot, nint targetRoot, bool foregroundIsOwn) =>
        pending && pendingFor < PendingTimeout && !foregroundIsOwn
        && targetRoot != 0 && foregroundRoot == targetRoot;

    public const string RegisteredMask = "********";
    public static string PemBodyMask => CoreStrings.PemBodyMask;

    private static bool IsPemHeader(SecretMatch m) =>
        m.Kind == SecretKind.ApiKey && m.Masked.StartsWith("-----BEGIN ", StringComparison.Ordinal)
                                   && m.Masked.EndsWith("PRIVATE KEY-----", StringComparison.Ordinal);
}
