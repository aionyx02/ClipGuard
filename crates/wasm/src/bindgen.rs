//! wasm-bindgen exports (TS wrapper: `packages/core-js/src/index.ts`).
//!
//! Every function takes and returns strings; JSON is parsed on the JS side.
//! Errors become JS exceptions whose message never contains the input text.

use wasm_bindgen::prelude::*;

use crate::api;

/// Analyzes `text`; `opts_json` is TS `AnalyzeOptions` as JSON (may be empty).
/// Returns the Report (§2.2) as JSON.
#[wasm_bindgen]
pub fn analyze(text: &str, opts_json: &str) -> Result<String, JsError> {
    api::analyze_with_json(text, opts_json).map_err(|e| JsError::new(&e.0))
}

/// "Paste masked": `report_json` is the Report returned by `analyze(text)`.
#[wasm_bindgen]
pub fn mask(text: &str, report_json: &str, locale: &str) -> Result<String, JsError> {
    api::mask_with_report_json(text, report_json, locale).map_err(|e| JsError::new(&e.0))
}

/// All `ui-*` strings of `locale` as a JSON object.
#[wasm_bindgen]
pub fn messages(locale: &str) -> String {
    api::messages(locale)
}

/// Deobfuscation trace and masked output preview as JSON.
#[wasm_bindgen]
pub fn deobfuscate(text: &str, locale: &str) -> String {
    api::deobfuscate_json(text, locale)
}

#[wasm_bindgen]
pub fn engine_version() -> String {
    api::ENGINE_VERSION.to_owned()
}
