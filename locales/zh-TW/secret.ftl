# Secret detection (zh-TW). Legacy CoreStrings.zh-TW.resx `RuleLabel_<id>` and `PemBodyMask`.

# Display name of a secret rule. `$id` is the rule id; rules without a translation
# show the rule file's `$label`.
secret-rule-label = { $id ->
    [sk-api-key] API key（sk-）
    [private-key-pem] 私鑰（PEM）
    [context-assignment] 疑似金鑰或密碼
    [context-authorization] Authorization 權杖
    [tw-national-id] 身分證字號
    [tw-resident-certificate] 居留證號
    [tw-ubn] 統一編號
    [tw-mobile] 手機號碼
    [credit-card] 信用卡號
    [iban] IBAN 帳號
    [e164-phone] 電話號碼（國際格式）
    [cn-resident-id] 中國居民身分證號
    [hk-id] 香港身分證號
    [hk-id-plain] 香港身分證號
    [jp-my-number] 個人番號（My Number）
    [kr-rrn] 住民登錄號碼（韓國）
    [sg-nric] 新加坡 NRIC
    [sg-fin] 新加坡 FIN
    [us-ssn] 社會安全號碼（SSN）
   *[other] { $label }
}

