//! macOS integration (docs/plan/phase-4.md §4.9.1, docs/spikes/s4-macos-monitor.md).
//!
//! AppKit / CoreGraphics calls are `unsafe`; like `windows`, this module is
//! allowed to use it. Every `unsafe` block states why it is sound, and
//! clipboard text only ever lives in zeroized buffers.
#![allow(unsafe_code)]
