//! Configuration guards: no network for the app (AI off, CLAUDE.md), each
//! window only gets its own commands (§4.3), every id the worker emits has a
//! translation.

use paste_warden_i18n::Localizer;
use serde_json::Value;

const CONF: &str = include_str!("../tauri.conf.json");
const CAPS: &[(&str, &str)] = &[
    ("settings", include_str!("../capabilities/settings.json")),
    ("confirm", include_str!("../capabilities/confirm.json")),
    (
        "onboarding",
        include_str!("../capabilities/onboarding.json"),
    ),
];
const CARGO: &str = include_str!("../Cargo.toml");

fn conf() -> Value {
    serde_json::from_str(CONF).unwrap()
}

#[test]
fn csp_allows_no_remote_origin() {
    let csp = conf()["app"]["security"]["csp"]
        .as_str()
        .unwrap()
        .to_owned();
    for directive in csp.split(';') {
        for src in directive.split_whitespace().skip(1) {
            let ok = matches!(
                src,
                "'self'" | "'none'" | "'unsafe-inline'" | "data:" | "ipc:" | "http://ipc.localhost"
            );
            assert!(ok, "unexpected CSP source {src}");
        }
    }
}

#[test]
fn no_network_capable_dependency_or_permission() {
    for banned in [
        "tauri-plugin-http",
        "reqwest",
        "ureq",
        "hyper",
        "tauri-plugin-updater",
    ] {
        assert!(!CARGO.contains(banned), "{banned}");
    }
    for (_, cap) in CAPS {
        let v: Value = serde_json::from_str(cap).unwrap();
        for p in v["permissions"].as_array().unwrap() {
            let p = p.as_str().unwrap();
            assert!(!p.starts_with("http:") && !p.starts_with("shell:"), "{p}");
        }
    }
}

#[test]
fn each_window_gets_only_its_commands() {
    for (window, cap) in CAPS {
        let v: Value = serde_json::from_str(cap).unwrap();
        assert_eq!(v["windows"], serde_json::json!([window]));
        let perms: Vec<&str> = v["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        let has = |p: &str| perms.contains(&p);
        match *window {
            "confirm" => {
                assert!(has("allow-paste-choice") && has("allow-get-pending-paste"));
                assert!(!has("allow-register-secret") && !has("allow-quit"));
            }
            "onboarding" => assert!(!has("allow-paste-choice") && !has("allow-register-secret")),
            _ => assert!(!has("allow-paste-choice")),
        }
    }
}

#[test]
fn bundle_targets_and_identity() {
    let c = conf();
    assert_eq!(c["productName"], "PasteWarden");
    assert_eq!(c["identifier"], "org.pastewarden.app");
    assert_eq!(
        c["bundle"]["targets"],
        serde_json::json!(["msi", "nsis", "dmg", "appimage", "deb"])
    );
    assert_eq!(c["bundle"]["macOS"]["signingIdentity"], "-");
}

/// Ids the Rust side renders itself (tray, toasts, errors).
#[test]
fn native_ids_are_translated() {
    let ids = [
        "ui-desktop-tray-status-normal",
        "ui-desktop-tray-status-degraded",
        "ui-desktop-tray-status-failed",
        "ui-desktop-tray-restore",
        "ui-desktop-tray-register-secret",
        "ui-desktop-tray-manage-secrets",
        "ui-desktop-tray-paste-menu",
        "ui-desktop-tray-strict-registered",
        "ui-desktop-tray-strict-detected",
        "ui-desktop-tray-allowlist",
        "ui-desktop-tray-settings",
        "ui-desktop-tray-quit",
        "ui-desktop-toast-quarantine-title",
        "ui-desktop-toast-quarantine-head",
        "ui-desktop-toast-quarantine-tail",
        "ui-desktop-toast-suspicious-title",
        "ui-desktop-toast-suspicious-head",
        "ui-desktop-toast-secret-title",
        "ui-desktop-toast-secret-line",
        "ui-desktop-toast-secret-more",
        "ui-desktop-toast-secret-advice",
        "ui-desktop-toast-hidden-title",
        "ui-desktop-toast-hidden-head",
        "ui-desktop-toast-wallet-swap-title",
        "ui-desktop-toast-wallet-swap-detail",
        "ui-desktop-toast-wallet-swap-detail-other",
        "ui-desktop-toast-wallet-swap-advice",
        "ui-desktop-toast-elevated-title",
        "ui-desktop-toast-elevated-unprotected",
        "ui-desktop-toast-secure-input-title",
        "ui-desktop-toast-secure-input-unprotected",
        "ui-desktop-toast-not-pasted-title",
        "ui-desktop-toast-paste-timeout",
        "ui-desktop-toast-cannot-read",
        "ui-desktop-toast-cannot-write",
        "ui-desktop-toast-cannot-send",
        "ui-desktop-toast-still-masked-title",
        "ui-desktop-toast-still-masked-body",
        "ui-desktop-toast-restore-failed-title",
        "ui-desktop-toast-restore-failed-body",
        "ui-desktop-toast-settings-problem-title",
        "ui-desktop-error-save-failed",
        "ui-desktop-error-store-corrupt",
        "ui-desktop-error-key-unavailable",
        "ui-desktop-error-worker-stopped",
        "ui-desktop-error-invalid-argument",
        "ui-desktop-error-allowlist-empty",
        "ui-desktop-error-allowlist-too-long",
        "ui-desktop-error-allowlist-duplicate",
        "ui-desktop-error-allowlist-full",
        "ui-desktop-error-allowlist-missing",
        "ui-desktop-error-label-too-long",
        "ui-desktop-error-secrets-full",
        "ui-desktop-error-secret-missing",
        "ui-desktop-error-no-pending-paste",
        "ui-desktop-error-nothing-to-restore",
        "ui-desktop-error-restore-failed",
        "ui-desktop-error-open-settings-failed",
        "ui-desktop-error-unsupported",
    ];
    for locale in ["en", "zh-TW"] {
        let (loc, errors) = Localizer::try_new(locale);
        assert!(errors.is_empty(), "{locale}: {errors:?}");
        for id in ids {
            assert!(loc.has(id), "{locale} is missing {id}");
        }
    }
}
