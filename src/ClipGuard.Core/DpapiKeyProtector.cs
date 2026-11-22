using System.Runtime.Versioning;
using System.Security.Cryptography;

namespace ClipGuard.Core;

/// <summary>
/// 用 Windows DPAPI（CurrentUser）保護金鑰：只有同一個 Windows 使用者登入時才解得開，
/// 換帳號或把檔案複製到別台電腦都無法解密。
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class DpapiKeyProtector : IKeyProtector
{
    // 額外的 entropy 讓別的程式即使也用 CurrentUser DPAPI，也不能直接拿這把金鑰去用。
    private static readonly byte[] Entropy = "ClipGuard.RegisteredSecrets.v1"u8.ToArray();

    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, Entropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] protectedData) =>
        ProtectedData.Unprotect(protectedData, Entropy, DataProtectionScope.CurrentUser);
}
