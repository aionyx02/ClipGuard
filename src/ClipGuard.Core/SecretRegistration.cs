namespace ClipGuard.Core;

public enum RegistrationField
{
    Label,
    Secret,
    Confirm,
}

/// <summary>登記機密的輸入哪一欄有問題；訊息顯示在那一欄旁邊，不含輸入的內容。</summary>
public sealed record RegistrationError(RegistrationField Field, string Message);

/// <summary>「登記機密」對話框的輸入檢查（#24 F19）。純邏輯；長度規則跟 <see cref="RegisteredSecretStore"/> 相同。</summary>
public static class SecretRegistration
{
    /// <summary>沒問題回傳 null。標籤可以留空（存成「未命名」）。重複登記要等寫入時由 store 判斷。</summary>
    public static RegistrationError? Validate(string? secret, string? confirm)
    {
        secret ??= "";
        confirm ??= "";
        if (secret.Length == 0)
            return new(RegistrationField.Secret, "請輸入要登記的機密。");
        if (secret.Length is < RegisteredSecretStore.MinLength or > RegisteredSecretStore.MaxLength)
            return new(RegistrationField.Secret,
                $"機密長度需 {RegisteredSecretStore.MinLength}–{RegisteredSecretStore.MaxLength} 字元，目前 {secret.Length} 字元。");
        if (confirm.Length == 0)
            return new(RegistrationField.Confirm, "請再輸入一次機密。");
        if (secret != confirm)
            return new(RegistrationField.Confirm, "兩次輸入的內容不一樣，請重新輸入。");
        return null;
    }
}
