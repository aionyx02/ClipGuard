//! What PasteWarden can protect right now (docs/plan/phase-4.md §4.8.1,
//! §4.9.4). Platform-independent, pure logic.
//!
//! Only `pw-work` changes a [`ProtectionStatus`]; every change is emitted to
//! the UI as `protection-status`. Like core, this crate produces no
//! human-readable text: each [`Reason`] maps to one Fluent message
//! `ui-desktop-status-<reason>` ([`Reason::message_id`]).

/// One protection area.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Capability {
    #[default]
    Active,
    /// Works, with a gap the user should know about.
    Degraded(Reason),
    /// Does not work at all.
    Unavailable(Reason),
}

impl Capability {
    pub fn reason(self) -> Option<Reason> {
        match self {
            Capability::Active => None,
            Capability::Degraded(r) | Capability::Unavailable(r) => Some(r),
        }
    }

    pub fn is_active(self) -> bool {
        self == Capability::Active
    }

    /// `"active"`, `"degraded"` or `"unavailable"` (UI / JSON).
    pub fn state_id(self) -> &'static str {
        match self {
            Capability::Active => "active",
            Capability::Degraded(_) => "degraded",
            Capability::Unavailable(_) => "unavailable",
        }
    }
}

/// Why a [`Capability`] is not [`Capability::Active`] (§4.8.1, §4.9.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    // 4a (Windows)
    /// The paste hook stopped answering probes (§4.4 hook health check).
    HookLost,
    /// The foreground window runs elevated; UIPI hides its keys (§4.8.2).
    ElevatedForeground,
    /// Turned off in settings.
    DisabledInSettings,
    // 4b (§4.9.4)
    SecureInput,
    NoAccessibility,
    NoAccessibilityAfterUpdate,
    PasteboardAccessAsk,
    PasteboardAccessDenied,
    NoDataControl,
    XWaylandUnverified,
    CosmicDisabled,
    NoForeignToplevel,
    WaylandNoIntercept,
    X11NoIntercept,
    NoDisplay,
    NoSecretService,
    AndroidNoBackground,
}

impl Reason {
    pub const ALL: [Reason; 17] = [
        Reason::HookLost,
        Reason::ElevatedForeground,
        Reason::DisabledInSettings,
        Reason::SecureInput,
        Reason::NoAccessibility,
        Reason::NoAccessibilityAfterUpdate,
        Reason::PasteboardAccessAsk,
        Reason::PasteboardAccessDenied,
        Reason::NoDataControl,
        Reason::XWaylandUnverified,
        Reason::CosmicDisabled,
        Reason::NoForeignToplevel,
        Reason::WaylandNoIntercept,
        Reason::X11NoIntercept,
        Reason::NoDisplay,
        Reason::NoSecretService,
        Reason::AndroidNoBackground,
    ];

    /// Kebab-case id, e.g. `"hook-lost"`.
    pub fn id(self) -> &'static str {
        match self {
            Reason::HookLost => "hook-lost",
            Reason::ElevatedForeground => "elevated-foreground",
            Reason::DisabledInSettings => "disabled-in-settings",
            Reason::SecureInput => "secure-input",
            Reason::NoAccessibility => "no-accessibility",
            Reason::NoAccessibilityAfterUpdate => "no-accessibility-after-update",
            Reason::PasteboardAccessAsk => "pasteboard-access-ask",
            Reason::PasteboardAccessDenied => "pasteboard-access-denied",
            Reason::NoDataControl => "no-data-control",
            Reason::XWaylandUnverified => "xwayland-unverified",
            Reason::CosmicDisabled => "cosmic-disabled",
            Reason::NoForeignToplevel => "no-foreign-toplevel",
            Reason::WaylandNoIntercept => "wayland-no-intercept",
            Reason::X11NoIntercept => "x11-no-intercept",
            Reason::NoDisplay => "no-display",
            Reason::NoSecretService => "no-secret-service",
            Reason::AndroidNoBackground => "android-no-background",
        }
    }

    /// Fluent message id: `ui-desktop-status-<id>`.
    pub fn message_id(self) -> String {
        format!("ui-desktop-status-{}", self.id())
    }
}

/// §4.8.1. `Default` is everything active.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ProtectionStatus {
    /// Background clipboard monitoring.
    pub watch: Capability,
    /// Clearing, masked write-back, restore.
    pub write: Capability,
    /// Foreground window (entry warnings, allowlist).
    pub foreground: Capability,
    /// Interception before paste.
    pub intercept: Capability,
}

/// The tray icon's three states (§4.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrayState {
    Normal,
    /// Any area is degraded (or unavailable while not critical).
    Degraded,
    /// `watch` or `intercept` is unavailable although enabled in settings.
    Failed,
}

impl ProtectionStatus {
    pub fn areas(&self) -> [(&'static str, Capability); 4] {
        [
            ("watch", self.watch),
            ("write", self.write),
            ("foreground", self.foreground),
            ("intercept", self.intercept),
        ]
    }

    /// Tray state. An area turned off in settings
    /// ([`Reason::DisabledInSettings`]) never makes the icon look broken.
    pub fn tray_state(&self) -> TrayState {
        let by_choice = |c: Capability| c.reason() == Some(Reason::DisabledInSettings);
        let failed = |c: Capability| matches!(c, Capability::Unavailable(_)) && !by_choice(c);
        if failed(self.watch) || failed(self.intercept) {
            return TrayState::Failed;
        }
        if self
            .areas()
            .iter()
            .any(|(_, c)| !c.is_active() && !by_choice(*c))
        {
            TrayState::Degraded
        } else {
            TrayState::Normal
        }
    }

    /// Reasons to list in the tray tooltip, in area order, without
    /// duplicates or settings choices.
    pub fn tooltip_reasons(&self) -> Vec<Reason> {
        let mut out = Vec::new();
        for (_, c) in self.areas() {
            if let Some(r) = c.reason()
                && r != Reason::DisabledInSettings
                && !out.contains(&r)
            {
                out.push(r);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_kebab_case() {
        let mut seen = std::collections::HashSet::new();
        for r in Reason::ALL {
            assert!(seen.insert(r.id()), "{r:?}");
            assert!(
                r.id()
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            );
            assert!(r.message_id().starts_with("ui-desktop-status-"));
        }
    }

    #[test]
    fn tray_states() {
        let mut s = ProtectionStatus::default();
        assert_eq!(s.tray_state(), TrayState::Normal);
        s.intercept = Capability::Degraded(Reason::ElevatedForeground);
        assert_eq!(s.tray_state(), TrayState::Degraded);
        assert_eq!(s.tooltip_reasons(), vec![Reason::ElevatedForeground]);
        s.intercept = Capability::Unavailable(Reason::DisabledInSettings);
        assert_eq!(s.tray_state(), TrayState::Normal);
        assert!(s.tooltip_reasons().is_empty());
        s.intercept = Capability::Unavailable(Reason::NoAccessibility);
        assert_eq!(s.tray_state(), TrayState::Failed);
        s.intercept = Capability::Active;
        s.foreground = Capability::Unavailable(Reason::NoForeignToplevel);
        assert_eq!(s.tray_state(), TrayState::Degraded);
    }
}
