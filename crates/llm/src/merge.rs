//! Guardrail ④: the model can only raise the Tier 1 verdict, never lower it.

use paste_warden_core::{Action, Level};

/// The higher of the Tier 1 level and the model's level.
pub fn merge(tier1: Level, llm: Option<Level>) -> Level {
    match llm {
        Some(l) => tier1.max(l),
        None => tier1,
    }
}

/// The action after Tier 2: the Tier 1 action, raised to what the model's
/// level implies under the default settings (malicious → quarantine,
/// suspicious → warn). Never lower than `tier1`.
pub fn merge_action(tier1: Action, llm: Option<Level>) -> Action {
    let implied = match llm {
        Some(Level::Malicious) => Action::Quarantine,
        Some(Level::Suspicious) => Action::Warn,
        Some(Level::None) | None => Action::Allow,
    };
    tier1.max(implied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn level() -> impl Strategy<Value = Level> {
        prop_oneof![
            Just(Level::None),
            Just(Level::Suspicious),
            Just(Level::Malicious)
        ]
    }

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Allow),
            Just(Action::Warn),
            Just(Action::Quarantine)
        ]
    }

    proptest! {
        #[test]
        fn merged_level_is_never_below_tier1(t in level(), l in proptest::option::of(level())) {
            let m = merge(t, l);
            prop_assert!(m >= t);
            if let Some(l) = l {
                prop_assert!(m >= l);
                prop_assert!(m == t || m == l);
            } else {
                prop_assert_eq!(m, t);
            }
        }

        #[test]
        fn merged_action_is_never_below_tier1(t in action(), l in proptest::option::of(level())) {
            prop_assert!(merge_action(t, l) >= t);
        }
    }

    #[test]
    fn model_cannot_downgrade() {
        assert_eq!(merge(Level::Malicious, Some(Level::None)), Level::Malicious);
        assert_eq!(
            merge_action(Action::Quarantine, Some(Level::None)),
            Action::Quarantine
        );
        assert_eq!(
            merge_action(Action::Allow, Some(Level::Malicious)),
            Action::Quarantine
        );
        assert_eq!(
            merge_action(Action::Allow, Some(Level::Suspicious)),
            Action::Warn
        );
    }
}
