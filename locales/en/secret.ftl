# Secret detection (en). Legacy CoreStrings.resx `RuleLabel_<id>` and `PemBodyMask`.

# Display name of a secret rule. `$id` is the rule id; rules without a translation
# show the rule file's `$label`.
secret-rule-label = { $id ->
    [sk-api-key] API key (sk-)
    [private-key-pem] Private key (PEM)
    [context-assignment] Possible key or password
    [context-authorization] Authorization token
    [tw-national-id] Taiwan ID number
    [tw-resident-certificate] Taiwan resident certificate number
    [tw-ubn] Taiwan business ID (UBN)
    [tw-mobile] Mobile number
    [credit-card] Credit card number
    [iban] IBAN
    [e164-phone] Phone number (international)
    [cn-resident-id] China resident ID number
    [hk-id] Hong Kong ID number
    [hk-id-plain] Hong Kong ID number
    [jp-my-number] Japan My Number
    [kr-rrn] Korea resident registration number
    [sg-nric] Singapore NRIC
    [sg-fin] Singapore FIN
    [us-ssn] US Social Security number (SSN)
    [context-assignment-cjk] Possible key or password
    [conn-string-url] Database password (connection string)
    [conn-string-odbc] Database password (connection string)
    [bip39-mnemonic] Wallet recovery phrase ({ $words } words)
   *[other] { $label }
}

