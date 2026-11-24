//! Adapters for `policy` ops. See `corpus/ops/policy*.md` for op definitions.

use anyhow::Result;

use crate::{Ctx, Expect};

pub fn run(_op: &str, _ctx: &Ctx<'_>, _exp: &mut Expect) -> Option<Result<()>> {
    None
}
