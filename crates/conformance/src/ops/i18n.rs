//! Adapters for `i18n` ops. See `corpus/ops/i18n*.md` for op definitions.
//! (`i18n.localized` is handled by the dispatcher.)

use anyhow::Result;
use paste_warden_i18n::locale::{map_locale, resolve_locale};

use crate::{Ctx, Expect};

pub fn run(op: &str, ctx: &Ctx<'_>, exp: &mut Expect) -> Option<Result<()>> {
    match op {
        "i18n.map_locale" => {
            let system = ctx.arg_str("system").unwrap_or_default();
            exp.eq("locale", map_locale(system));
            Some(Ok(()))
        }
        "i18n.resolve_locale" => {
            let argv = ctx.arg_strings("argv").unwrap_or_default();
            let env = ctx.arg_str("env");
            let system = ctx.arg_str("system").unwrap_or_default();
            exp.eq("locale", resolve_locale(&argv, env, system));
            Some(Ok(()))
        }
        "i18n.display_label" => {
            let locale = ctx.arg_str("locale").unwrap_or("zh-TW");
            let rule = ctx.arg_str("rule").unwrap_or_default();
            let label = ctx.arg_str("label").unwrap_or_default();
            let msg = paste_warden_core::secret::rule_label(rule, label);
            exp.eq("text", crate::localizer(locale).format(&msg));
            Some(Ok(()))
        }
        _ => None,
    }
}
