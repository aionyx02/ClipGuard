//! Adapters for `hidden` ops. See `corpus/ops/hidden*.md` for op definitions.

use anyhow::Result;

use crate::{Ctx, Expect};

pub fn run(_op: &str, _ctx: &Ctx<'_>, _exp: &mut Expect) -> Option<Result<()>> {
    None
}

/// Benign-corpus classification for this area (see [`super::BenignVerdict`]).
pub fn benign(_input: &str) -> Option<Result<super::BenignVerdict>> {
    None
}
