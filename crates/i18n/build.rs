//! Embeds every `locales/<lang>/*.ftl` file into the crate.
use std::fmt::Write as _;
use std::path::Path;

fn main() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../locales");
    println!("cargo:rerun-if-changed={}", root.display());
    let mut entries = Vec::new();
    if let Ok(langs) = std::fs::read_dir(&root) {
        for lang in langs.flatten() {
            let path = lang.path();
            if !path.is_dir() {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let name = lang.file_name().to_string_lossy().into_owned();
            let mut files: Vec<_> = std::fs::read_dir(&path)
                .into_iter()
                .flatten()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "ftl"))
                .collect();
            files.sort();
            for f in files {
                println!("cargo:rerun-if-changed={}", f.display());
                entries.push((name.clone(), f));
            }
        }
    }
    entries.sort();
    let mut out = String::from("pub(crate) const FILES: &[(&str, &str, &str)] = &[\n");
    for (lang, f) in entries {
        let file = f.file_name().unwrap().to_string_lossy().into_owned();
        let abs = f.canonicalize().unwrap();
        writeln!(
            out,
            "    ({lang:?}, {file:?}, include_str!({:?})),",
            abs.display().to_string()
        )
        .unwrap();
    }
    out.push_str("];\n");
    let dest = Path::new(&std::env::var("OUT_DIR").unwrap()).join("locales.rs");
    std::fs::write(dest, out).unwrap();
}
