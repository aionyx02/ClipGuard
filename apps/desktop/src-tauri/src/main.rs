//! PasteWarden desktop app (docs/plan/phase-4.md).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    paste_warden_desktop::run();
}
