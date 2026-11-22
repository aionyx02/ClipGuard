using System.Security.Cryptography;
using System.Text;
using ClipGuard.Core;

namespace ClipGuard.Core.Tests;

public sealed class RegisteredSecretStoreTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "ClipGuardTests", Guid.NewGuid().ToString("N"));

    // 測試用的假保護：XOR 固定值。只用來確認 store 有經過 protector，不是安全實作。
    private sealed class FakeProtector : IKeyProtector
    {
        public int ProtectCalls;
        public byte[] Protect(byte[] p) { ProtectCalls++; return p.Select(b => (byte)(b ^ 0x5A)).ToArray(); }
        public byte[] Unprotect(byte[] p) => p.Select(b => (byte)(b ^ 0x5A)).ToArray();
    }

    private sealed class BrokenProtector : IKeyProtector
    {
        public byte[] Protect(byte[] p) => p;
        public byte[] Unprotect(byte[] p) => throw new CryptographicException("not mine");
    }

    public void Dispose()
    {
        if (Directory.Exists(_dir)) Directory.Delete(_dir, recursive: true);
    }

    private RegisteredSecretStore NewStore(IKeyProtector? p = null) => new(_dir, p ?? new FakeProtector());

    [Fact]
    public void 登記後在文字中找得到_只回報標籤()
    {
        var store = NewStore();
        store.Add("網銀密碼", "Tr0ub4dor&3");

        var m = Assert.Single(store.Find("帳號 alice 密碼 Tr0ub4dor&3 謝謝"));
        Assert.Equal(SecretKind.Registered, m.Kind);
        Assert.Equal("網銀密碼", m.Label);
        Assert.Equal(12, m.Index);
        Assert.Equal(11, m.Length);
        Assert.DoesNotContain("Tr0", m.Masked);
        Assert.DoesNotContain("&3", m.Masked);
    }

    [Fact]
    public void 沒登記或差一個字都不會命中()
    {
        var store = NewStore();
        store.Add("pin", "246813579");
        Assert.Empty(store.Find("246813578"));
        Assert.Empty(store.Find("24681357"));
        Assert.Empty(store.Find("毫無關係的文字"));
        Assert.Empty(store.Find(null));
    }

    [Fact]
    public void 多個不同長度的項目都能比對()
    {
        var store = NewStore();
        store.Add("a", "secret-one");
        store.Add("b", "another-secret-two");
        var found = store.Find("x another-secret-two y secret-one z");
        Assert.Equal(["b", "a"], found.Select(m => m.Label));
    }

    [Fact]
    public void 檔案只存長度與HMAC_不存原文也不是SHA256()
    {
        const string secret = "MyS3cretValue!";
        NewStore().Add("test", secret);

        var json = File.ReadAllText(Path.Combine(_dir, "secrets.json"));
        Assert.DoesNotContain(secret, json);
        Assert.Contains("\"Length\": 14", json);

        var plainSha = Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret)));
        Assert.DoesNotContain(plainSha, json);
    }

    [Fact]
    public void 重新開啟後仍可比對_金鑰只產生一次()
    {
        var p = new FakeProtector();
        new RegisteredSecretStore(_dir, p).Add("x", "persisted-secret");
        var reopened = new RegisteredSecretStore(_dir, p);

        Assert.Equal(1, p.ProtectCalls);
        Assert.Single(reopened.Entries);
        Assert.Single(reopened.Find("persisted-secret"));
    }

    [Fact]
    public void 不同金鑰的HMAC不同()
    {
        var a = new RegisteredSecretStore(Path.Combine(_dir, "a"), new FakeProtector()).Add("x", "same-secret");
        var b = new RegisteredSecretStore(Path.Combine(_dir, "b"), new FakeProtector()).Add("x", "same-secret");
        Assert.NotEqual(a.Hmac, b.Hmac);
    }

    [Fact]
    public void 移除後不再命中()
    {
        var store = NewStore();
        var e = store.Add("x", "remove-me-please");
        Assert.True(store.Remove(e.Id));
        Assert.Empty(store.Find("remove-me-please"));
        Assert.Empty(NewStore().Entries);
        Assert.False(store.Remove(Guid.NewGuid()));
    }

    [Theory]
    [InlineData("short")]
    [InlineData("")]
    public void 太短不接受(string secret) =>
        Assert.Throws<ArgumentException>(() => NewStore().Add("x", secret));

    [Fact]
    public void 重複登記拒絕()
    {
        var store = NewStore();
        store.Add("x", "duplicate-secret");
        Assert.Throws<InvalidOperationException>(() => store.Add("y", "duplicate-secret"));
    }

    [Fact]
    public void 金鑰解不開時丟例外而不是默默重建()
    {
        NewStore().Add("x", "some-secret");
        Assert.ThrowsAny<CryptographicException>(() => NewStore(new BrokenProtector()));
    }

    [Fact]
    public void 金鑰遺失時舊項目一起清掉()
    {
        NewStore().Add("x", "some-secret");
        File.Delete(Path.Combine(_dir, "key.bin"));
        Assert.Empty(NewStore().Entries);
    }

    [Fact]
    public void 非ASCII機密也能比對()
    {
        var store = NewStore();
        store.Add("中文", "我的祕密密碼🔑");
        Assert.Single(store.Find("前綴我的祕密密碼🔑後綴"));
    }

    [Fact]
    public void DPAPI可以往返()
    {
        if (!OperatingSystem.IsWindows()) return;
        var p = new DpapiKeyProtector();
        var key = RandomNumberGenerator.GetBytes(32);
        var protectedKey = p.Protect(key);
        Assert.NotEqual(key, protectedKey);
        Assert.Equal(key, p.Unprotect(protectedKey));

        var store = new RegisteredSecretStore(_dir, p);
        store.Add("x", "dpapi-backed-secret");
        Assert.Single(new RegisteredSecretStore(_dir, p).Find("dpapi-backed-secret"));
    }
}
