//! Plain C-ABI exports for the wasm2js fallback (`raw-abi` feature; S2).
//!
//! wasm-bindgen 0.2's output uses an externref table that binaryen `wasm2js`
//! cannot convert, so the fallback build talks to the module through these
//! functions and the exported `memory` only. The JS glue is
//! `packages/core-js/src/raw.ts`.
//!
//! Protocol:
//! - Inputs: the caller gets a buffer with [`pw_alloc`]`(len)`, writes UTF-8
//!   bytes into it, passes `(ptr, len)` and afterwards frees it with
//!   [`pw_free`]`(ptr, len)`. Invalid UTF-8 is replaced (lossy), never trusted.
//! - Outputs: every `pw_*` call returns a pointer to a result buffer laid out as
//!   `[u32 little-endian payload length][u8 status][payload UTF-8]`, status 0 =
//!   ok, 1 = error (payload is the error message, which never contains the
//!   input). The caller frees it with `pw_free(ptr, 5 + payload length)`.
//!
//! This is the only module of the workspace allowed to use `unsafe`: handing
//! raw pointers into linear memory across the ABI cannot be done without it.
// SAFETY (module-wide): see the comment on each block. The caller (our own JS
// glue) must pass pointers obtained from `pw_alloc` with the same length.
#![allow(unsafe_code)]

use crate::api;

/// Header size of a result buffer (length + status).
pub const RESULT_HEADER: usize = 5;

/// Allocates `len` zeroed bytes in linear memory and returns the pointer.
#[unsafe(no_mangle)]
pub extern "C" fn pw_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
}

/// Frees a buffer returned by [`pw_alloc`] or by any `pw_*` call.
///
/// # Safety
/// `ptr` must come from [`pw_alloc`]`(len)` or be a result buffer of exactly
/// `len` bytes, and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: per the contract above, `ptr..ptr+len` is a boxed slice we leaked.
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

/// Reads `(ptr, len)` as text (lossy UTF-8).
///
/// # Safety
/// `ptr..ptr+len` must be readable (a [`pw_alloc`] buffer) or `len` must be 0.
unsafe fn read(ptr: *const u8, len: usize) -> String {
    if ptr.is_null() || len == 0 {
        return String::new();
    }
    // SAFETY: the caller guarantees `ptr..ptr+len` is a live allocation.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

/// Packs a result into a leaked buffer (see the module docs).
fn result(r: Result<String, api::Error>) -> *mut u8 {
    let (status, payload) = match r {
        Ok(s) => (0u8, s),
        Err(e) => (1u8, e.0),
    };
    let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
    let mut buf = Vec::with_capacity(RESULT_HEADER + payload.len());
    buf.extend_from_slice(&len.to_le_bytes());
    buf.push(status);
    buf.extend_from_slice(&payload.as_bytes()[..len as usize]);
    Box::into_raw(buf.into_boxed_slice()).cast::<u8>()
}

/// `analyze(text, opts_json)` → Report JSON.
///
/// # Safety
/// Both `(ptr, len)` pairs must satisfy [`pw_free`]'s buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_analyze(
    text_ptr: *const u8,
    text_len: usize,
    opts_ptr: *const u8,
    opts_len: usize,
) -> *mut u8 {
    // SAFETY: forwarded caller contract.
    let (text, opts) = unsafe { (read(text_ptr, text_len), read(opts_ptr, opts_len)) };
    result(api::analyze_with_json(&text, &opts))
}

/// `mask(text, report_json, locale)` → masked text.
///
/// # Safety
/// Every `(ptr, len)` pair must satisfy [`pw_free`]'s buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_mask(
    text_ptr: *const u8,
    text_len: usize,
    report_ptr: *const u8,
    report_len: usize,
    locale_ptr: *const u8,
    locale_len: usize,
) -> *mut u8 {
    // SAFETY: forwarded caller contract.
    let (text, report, locale) = unsafe {
        (
            read(text_ptr, text_len),
            read(report_ptr, report_len),
            read(locale_ptr, locale_len),
        )
    };
    result(api::mask_with_report_json(&text, &report, &locale))
}

/// `messages(locale)` → JSON object of `ui-*` strings.
///
/// # Safety
/// `(locale_ptr, locale_len)` must satisfy [`pw_free`]'s buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_messages(locale_ptr: *const u8, locale_len: usize) -> *mut u8 {
    // SAFETY: forwarded caller contract.
    let locale = unsafe { read(locale_ptr, locale_len) };
    result(Ok(api::messages(&locale)))
}

/// `deobfuscate(text, locale)` → JSON.
///
/// # Safety
/// Both `(ptr, len)` pairs must satisfy [`pw_free`]'s buffer contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pw_deobfuscate(
    text_ptr: *const u8,
    text_len: usize,
    locale_ptr: *const u8,
    locale_len: usize,
) -> *mut u8 {
    // SAFETY: forwarded caller contract.
    let (text, locale) = unsafe { (read(text_ptr, text_len), read(locale_ptr, locale_len)) };
    result(Ok(api::deobfuscate_json(&text, &locale)))
}

/// Engine version string.
#[unsafe(no_mangle)]
pub extern "C" fn pw_engine_version() -> *mut u8 {
    result(Ok(api::ENGINE_VERSION.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(s: &str) -> (*mut u8, usize) {
        let p = pw_alloc(s.len());
        // SAFETY: `p` has `s.len()` bytes.
        unsafe { std::ptr::copy_nonoverlapping(s.as_ptr(), p, s.len()) };
        (p, s.len())
    }

    fn take(p: *mut u8) -> (u8, String) {
        // SAFETY: `p` is a result buffer: 4-byte length, status, payload.
        unsafe {
            let mut len = [0u8; 4];
            std::ptr::copy_nonoverlapping(p, len.as_mut_ptr(), 4);
            let len = u32::from_le_bytes(len) as usize;
            let status = *p.add(4);
            let payload = std::slice::from_raw_parts(p.add(RESULT_HEADER), len).to_vec();
            pw_free(p, RESULT_HEADER + len);
            (status, String::from_utf8(payload).unwrap())
        }
    }

    #[test]
    fn round_trip_through_the_c_abi() {
        let (t, tl) = input("😀 A123456789");
        let (o, ol) = input(r#"{"locale":"en"}"#);
        // SAFETY: buffers from `pw_alloc` with their lengths.
        let (status, json) = take(unsafe { pw_analyze(t, tl, o, ol) });
        assert_eq!(status, 0);
        assert_eq!(
            json,
            api::analyze_with_json("😀 A123456789", r#"{"locale":"en"}"#).unwrap()
        );
        let (l, ll) = input("en");
        let (r, rl) = input(&json);
        // SAFETY: as above.
        let (status, masked) = take(unsafe { pw_mask(t, tl, r, rl, l, ll) });
        assert_eq!((status, masked.as_str()), (0, "😀 A12****789"));
        // SAFETY: as above; an empty input may be null.
        let (status, err) = take(unsafe { pw_analyze(std::ptr::null(), 0, t, tl) });
        assert_eq!(status, 1);
        assert!(!err.contains("A123456789"));
        let (_, v) = take(pw_engine_version());
        assert_eq!(v, api::ENGINE_VERSION);
        // SAFETY: freeing our own inputs once.
        unsafe {
            for (p, n) in [(t, tl), (o, ol), (l, ll), (r, rl)] {
                pw_free(p, n);
            }
        }
    }
}
