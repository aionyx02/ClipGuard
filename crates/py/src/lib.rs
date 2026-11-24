//! Python module `paste_warden` (PyO3, abi3) for the red-team tooling
//! (docs/plan/phase-2.md §2.7, docs/integrations/wasm.md).
//!
//! Build with maturin (`crates/py/pyproject.toml`), which enables the `python`
//! feature. Without it the crate is empty, so plain `cargo` workspace builds do
//! not need Python.
//!
//! The JSON is produced by `paste_warden_report`, so Python gets exactly the
//! same Report as JS (§2.2): masked values only, UTF-16 spans.
#![forbid(unsafe_code)]

#[cfg(feature = "python")]
mod module {
    use paste_warden_core::Settings;
    use paste_warden_report::{self as api, AnalyzeOptions};
    use pyo3::exceptions::PyValueError;
    use pyo3::prelude::*;

    fn loads<'py>(py: Python<'py>, json: &str) -> PyResult<Bound<'py, PyAny>> {
        py.import("json")?.call_method1("loads", (json,))
    }

    /// Analyzes `text` and returns the Report (docs/plan/phase-2.md §2.2) as a
    /// dict. `packs` selects PII packs (default `universal` + `tw`).
    #[pyfunction]
    #[pyo3(signature = (text, locale = "zh-TW", *, packs = None))]
    fn analyze<'py>(
        py: Python<'py>,
        text: &str,
        locale: &str,
        packs: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let mut opts = AnalyzeOptions {
            locale: Some(locale.to_owned()),
            ..AnalyzeOptions::default()
        };
        if let Some(p) = packs {
            opts.settings.packs = p;
        }
        let json = py
            .detach(|| api::analyze(text, &opts))
            .map_err(|e| PyValueError::new_err(e.0))?;
        loads(py, &json)
    }

    /// `text` with every detected secret masked ("paste masked").
    #[pyfunction]
    #[pyo3(signature = (text, locale = "zh-TW"))]
    fn mask(py: Python<'_>, text: &str, locale: &str) -> String {
        py.detach(|| api::mask(text, &Settings::default(), locale))
    }

    /// Deobfuscation trace and a masked preview of the peeled text:
    /// `{"trace": [...], "output_preview": str, "capped": bool}`.
    #[pyfunction]
    #[pyo3(signature = (text, locale = "zh-TW"))]
    fn deobfuscate<'py>(py: Python<'py>, text: &str, locale: &str) -> PyResult<Bound<'py, PyAny>> {
        let json = py.detach(|| api::deobfuscate_json(text, locale));
        loads(py, &json)
    }

    #[pymodule]
    fn paste_warden(m: &Bound<'_, PyModule>) -> PyResult<()> {
        m.add_function(wrap_pyfunction!(analyze, m)?)?;
        m.add_function(wrap_pyfunction!(mask, m)?)?;
        m.add_function(wrap_pyfunction!(deobfuscate, m)?)?;
        m.add("ENGINE_VERSION", api::ENGINE_VERSION)?;
        m.add("__version__", api::ENGINE_VERSION)?;
        Ok(())
    }
}
