using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public class PasteGuardTests
{
    private static readonly PasteTarget Chat = new("Discord", "Chrome_WidgetWin_1");
    private static readonly PasteTarget Notepad = new("notepad", "Notepad");

    private static readonly SecretKind[] RegisteredOnly = [SecretKind.Registered];
    private static readonly SecretKind[] CardOnly = [SecretKind.CreditCard];

    [Fact]
    public void NoSecrets_Allows()
    {
        var all = new PasteGuardSettings { InterceptDetected = true };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide([], Chat, all));
    }

    [Fact]
    public void Defaults_InterceptRegisteredSecret()
    {
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, Chat, PasteGuardSettings.Default));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, Notepad, PasteGuardSettings.Default));
    }

    [Theory]
    [InlineData(SecretKind.CreditCard)]
    [InlineData(SecretKind.NationalId)]
    [InlineData(SecretKind.MobilePhone)]
    [InlineData(SecretKind.ApiKey)]
    [InlineData(SecretKind.BusinessId)]
    [InlineData(SecretKind.ResidentCertificate)]
    public void Defaults_DoNotInterceptDetectedSecrets(SecretKind kind)
    {
        // 個資、API key 的攔截要使用者自己打開，避免每次貼電話都要確認。
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide([kind], Chat, PasteGuardSettings.Default));
    }

    [Fact]
    public void OptIn_InterceptsDetectedSecrets()
    {
        var s = new PasteGuardSettings { InterceptDetected = true };
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(CardOnly, Chat, s));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide([SecretKind.ApiKey, SecretKind.MobilePhone], Chat, s));
    }

    [Fact]
    public void RegisteredOff_DetectedOn_OnlyDetectedIntercepted()
    {
        var s = new PasteGuardSettings { InterceptRegistered = false, InterceptDetected = true };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide(RegisteredOnly, Chat, s));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(CardOnly, Chat, s));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide([SecretKind.Registered, SecretKind.CreditCard], Chat, s));
    }

    [Fact]
    public void BothOff_NeverIntercepts()
    {
        var s = new PasteGuardSettings { InterceptRegistered = false, InterceptDetected = false };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide([SecretKind.Registered, SecretKind.ApiKey], Chat, s));
    }

    [Fact]
    public void MixedRegisteredAndDetected_DefaultsIntercept()
    {
        Assert.Equal(PasteDecision.Intercept,
            PasteGuard.Decide([SecretKind.CreditCard, SecretKind.Registered], Chat, PasteGuardSettings.Default));
    }

    [Theory]
    [InlineData("1Password")]
    [InlineData("KeePassXC")]
    [InlineData("keepass")]
    [InlineData("Bitwarden.exe")]
    [InlineData("CredentialUIBroker")]
    public void BuiltInPasswordManagers_Allowed(string process)
    {
        var s = new PasteGuardSettings { InterceptDetected = true };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide(RegisteredOnly, new PasteTarget(process, "X"), s));
    }

    [Fact]
    public void CredentialDialogClass_AllowedFromAnyProcess()
    {
        var target = new PasteTarget("explorer", "Credential Dialog Xaml Host");
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide(RegisteredOnly, target, PasteGuardSettings.Default));
    }

    [Fact]
    public void OwnProcess_AlwaysAllowed()
    {
        var own = new PasteTarget("ClipGuard.App", "WindowsForms10.Window.8.app.0.1", IsOwnProcess: true);
        var s = new PasteGuardSettings { InterceptDetected = true };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide([SecretKind.Registered, SecretKind.ApiKey], own, s));
    }

    [Theory]
    [InlineData("Signal")]
    [InlineData("signal.exe")]
    [InlineData(@"C:\Program Files\Signal\Signal.exe")]
    [InlineData("  SIGNAL  ")]
    public void UserAllowlist_MatchesNormalizedNames(string entry)
    {
        var s = new PasteGuardSettings { AllowedApps = [entry] };
        Assert.Equal(PasteDecision.Allow, PasteGuard.Decide(RegisteredOnly, new PasteTarget("Signal", "X"), s));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, Chat, s));
    }

    [Fact]
    public void Allowlist_IsExactName_NotSubstring()
    {
        // 「KeePass」在清單上，不代表「KeePassFake」或「Pass」也放行。
        var s = PasteGuardSettings.Default;
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, new PasteTarget("KeePassFake", "X"), s));
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, new PasteTarget("Pass", "X"), s));
    }

    [Fact]
    public void UnknownProcessName_IsNotAllowlisted()
    {
        var s = new PasteGuardSettings { AllowedApps = ["Signal"] };
        Assert.Equal(PasteDecision.Intercept, PasteGuard.Decide(RegisteredOnly, new PasteTarget("", "X"), s));
    }

    [Theory]
    [InlineData(false, false, false)]
    [InlineData(false, true, true)]
    [InlineData(true, false, true)]
    public void CanIntercept_ReflectsSettingsAndStore(bool hasRegistered, bool detected, bool expected)
    {
        var s = new PasteGuardSettings { InterceptDetected = detected };
        Assert.Equal(expected, s.CanIntercept(hasRegistered));
    }

    [Fact]
    public void Snapshot_KeepsOnlyKindsAndMasks()
    {
        const string card = "4111 1111 1111 1111";   // Visa 公開測試卡號
        var text = $"卡號 {card} 請勿外流";
        var snap = ClipboardSecretSnapshot.From(42, SecretDetector.Find(text));

        Assert.Equal(42u, snap.Sequence);
        var only = Assert.Single(snap.Secrets);
        Assert.Equal(SecretKind.CreditCard, only.Kind);
        Assert.DoesNotContain(card, only.Masked);
        Assert.DoesNotContain("41111111", only.Masked);
        Assert.Equal([SecretKind.CreditCard], snap.Kinds);
    }

    [Fact]
    public void MaskText_ReplacesDetectedSecretsInPlace()
    {
        var text = "卡號 4111 1111 1111 1111，手機 0912-345-678。";
        var masked = PasteGuard.MaskText(text, SecretDetector.Find(text));

        Assert.StartsWith("卡號 4111********1111，手機 091****678", masked);
        Assert.EndsWith("。", masked);
        Assert.DoesNotContain("1111 1111", masked);
        Assert.DoesNotContain("345", masked);
        Assert.Empty(SecretDetector.Find(masked));
    }

    [Fact]
    public void MaskText_RegisteredSecret_UsesFixedStarsWithoutLabel()
    {
        const string text = "密碼是 hunter2-fake 喔";
        var match = new SecretMatch(SecretKind.Registered, "網銀", "已登記的「網銀」", 4, 12);
        var masked = PasteGuard.MaskText(text, [match]);

        Assert.Equal("密碼是 " + PasteGuard.RegisteredMask + " 喔", masked);
        Assert.DoesNotContain("網銀", masked);
    }

    [Fact]
    public void MaskText_PemPrivateKey_MasksBodyUntilEndLine()
    {
        var text = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIFAKEFAKEFAKE\nABCDEF\n-----END RSA PRIVATE KEY-----\nbye";
        var masked = PasteGuard.MaskText(text, SecretDetector.Find(text));

        Assert.DoesNotContain("MIIFAKE", masked);
        Assert.DoesNotContain("ABCDEF", masked);
        Assert.Contains(PasteGuard.PemBodyMask, masked);
        Assert.EndsWith("-----END RSA PRIVATE KEY-----\nbye", masked);
    }

    [Fact]
    public void MaskText_PemWithoutEnd_MasksToEndOfText()
    {
        var text = "-----BEGIN PRIVATE KEY-----\nMIIFAKEFAKE";
        var masked = PasteGuard.MaskText(text, SecretDetector.Find(text));
        Assert.DoesNotContain("MIIFAKE", masked);
    }

    [Fact]
    public void MaskText_NoMatches_ReturnsOriginal()
    {
        Assert.Equal("hello", PasteGuard.MaskText("hello", []));
    }

    [Fact]
    public void MaskText_IgnoresOverlappingAndOutOfRangeMatches()
    {
        var a = new SecretMatch(SecretKind.ApiKey, "k", "AAA", 0, 4);
        var overlap = new SecretMatch(SecretKind.ApiKey, "k", "BBB", 2, 4);
        var outOfRange = new SecretMatch(SecretKind.ApiKey, "k", "CCC", 8, 10);
        Assert.Equal("AAA5678", PasteGuard.MaskText("12345678", [overlap, a, outOfRange]));
    }

    [Theory]
    [InlineData("Signal", "Signal")]
    [InlineData("signal.EXE", "signal")]
    [InlineData(@"C:\x\y\App.exe", "App")]
    [InlineData("   ", "")]
    [InlineData(null, "")]
    public void NormalizeAppName(string? input, string expected)
    {
        Assert.Equal(expected, PasteGuard.NormalizeAppName(input));
    }
}

public sealed class PasteGuardSettingsStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ClipGuardTests", Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    [Fact]
    public void MissingFile_ReturnsDefaults_AndDoesNotCreateFile()
    {
        var store = new PasteGuardSettingsStore(_dir);
        var s = store.Load(out var error);

        Assert.Null(error);
        Assert.True(s.InterceptRegistered);
        Assert.False(s.InterceptDetected);
        Assert.Empty(s.AllowedApps);
        Assert.False(File.Exists(Path.Combine(_dir, PasteGuardSettingsStore.FileName)));
    }

    [Fact]
    public void SaveThenLoad_RoundTrips_AndNormalizesApps()
    {
        var store = new PasteGuardSettingsStore(_dir);
        store.Save(new PasteGuardSettings
        {
            InterceptRegistered = false,
            InterceptDetected = true,
            AllowedApps = ["Signal.exe", "signal", "  ", @"C:\Apps\Telegram.exe"],
        });

        var s = store.Load(out var error);
        Assert.Null(error);
        Assert.False(s.InterceptRegistered);
        Assert.True(s.InterceptDetected);
        Assert.Equal(["Signal", "Telegram"], s.AllowedApps);
    }

    [Fact]
    public void CorruptFile_ReturnsDefaultsWithError()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, PasteGuardSettingsStore.FileName), "{ not json");
        var s = new PasteGuardSettingsStore(_dir).Load(out var error);

        Assert.NotNull(error);
        Assert.Equal(PasteGuardSettings.Default, s with { AllowedApps = PasteGuardSettings.Default.AllowedApps });
    }

    [Fact]
    public void PartialFile_UsesDefaultsForMissingFields()
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, PasteGuardSettingsStore.FileName), """{ "InterceptDetected": true }""");
        var s = new PasteGuardSettingsStore(_dir).Load(out _);

        Assert.True(s.InterceptRegistered);
        Assert.True(s.InterceptDetected);
        Assert.Empty(s.AllowedApps);
    }

    [Fact]
    public void Save_CapsAllowlistSize()
    {
        var store = new PasteGuardSettingsStore(_dir);
        store.Save(new PasteGuardSettings
        {
            AllowedApps = Enumerable.Range(0, 500).Select(i => $"app{i}").ToList(),
        });
        Assert.Equal(PasteGuardSettingsStore.MaxAllowedApps, store.Load(out _).AllowedApps.Count);
    }
}
