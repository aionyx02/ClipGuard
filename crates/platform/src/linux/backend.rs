//! Backend selection and the honest capability report (phase-4.md §4.8.1,
//! §4.9.2, §4.9.4; S5 "建議做法").
//!
//! Pure: the environment and the Wayland globals are passed in, so the
//! decision is unit-tested on every OS. Only [`super::monitor`] reads
//! environment variables and talks to the compositor.

/// Environment variables the selection depends on (read by the platform
/// layer, never by this module).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Env {
    /// `WAYLAND_DISPLAY`, when set and non-empty.
    pub wayland_display: Option<String>,
    /// `DISPLAY`, when set and non-empty.
    pub x11_display: Option<String>,
    /// `XDG_CURRENT_DESKTOP` (colon-separated list).
    pub current_desktop: Option<String>,
    /// `XDG_RUNTIME_DIR`, where a relative `WAYLAND_DISPLAY` socket lives.
    /// Not used by [`select`].
    pub runtime_dir: Option<String>,
}

/// `XDG_CURRENT_DESKTOP` entry of COSMIC (S5: data-control is only exposed
/// with `COSMIC_DATA_CONTROL_ENABLED=1`).
pub const COSMIC_ENV_HINT: &str = "COSMIC";
/// The variable COSMIC users have to set (shown by the UI, never read here).
pub const COSMIC_DATA_CONTROL_VAR: &str = "COSMIC_DATA_CONTROL_ENABLED";

impl Env {
    /// Builds an [`Env`] from raw variable values; empty values count as unset.
    pub fn from_vars(
        wayland_display: Option<String>,
        x11_display: Option<String>,
        current_desktop: Option<String>,
    ) -> Env {
        let clean = |v: Option<String>| v.filter(|s| !s.trim().is_empty());
        Env {
            wayland_display: clean(wayland_display),
            x11_display: clean(x11_display),
            current_desktop: clean(current_desktop),
            runtime_dir: None,
        }
    }

    /// The Wayland socket path (`WAYLAND_DISPLAY` absolute, or relative to
    /// `XDG_RUNTIME_DIR`).
    pub fn wayland_socket(&self) -> Option<std::path::PathBuf> {
        let name = self.wayland_display.as_deref()?;
        let path = std::path::Path::new(name);
        if path.is_absolute() {
            Some(path.to_owned())
        } else {
            Some(std::path::Path::new(self.runtime_dir.as_deref()?).join(path))
        }
    }

    /// `XDG_CURRENT_DESKTOP` lists COSMIC (case-insensitive).
    pub fn is_cosmic(&self) -> bool {
        self.current_desktop.as_deref().is_some_and(|d| {
            d.split(':')
                .any(|e| e.trim().eq_ignore_ascii_case(COSMIC_ENV_HINT))
        })
    }
}

/// Which relevant globals the Wayland registry advertised.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WaylandGlobals {
    /// `ext_data_control_manager_v1` (wayland-protocols staging).
    pub ext_data_control: bool,
    /// `zwlr_data_control_manager_v1` (deprecated, KWin 6.5 removed it).
    pub wlr_data_control: bool,
    /// `zwlr_foreign_toplevel_manager_v1` (has the `activated` state).
    pub wlr_foreign_toplevel: bool,
    /// At least one `wl_seat` (data-control devices are per seat).
    pub seat: bool,
}

/// The clipboard backend to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// `ext_data_control_manager_v1` (bound first, S5 pitfall 1).
    WaylandExt,
    /// `zwlr_data_control_manager_v1`.
    WaylandWlr,
    /// XFixes on the XWayland display of a Wayland session (unverified: on
    /// wlroots it misses native Wayland copies, S5 pitfall 3).
    XWayland,
    /// XFixes on a plain X11 session.
    X11,
    /// Nothing usable: no background monitoring.
    None,
}

/// How the foreground window is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForegroundSource {
    /// `_NET_ACTIVE_WINDOW` on X11.
    X11ActiveWindow,
    /// `zwlr_foreign_toplevel_manager_v1`.
    WlrForeignToplevel,
    None,
}

/// Mirrors `ProtectionStatus` reasons (phase-4.md §4.9.4). Each maps to the
/// Fluent message `ui-desktop-status-<reason>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// GNOME / Mutter: no data-control protocol.
    NoDataControl,
    /// Only XWayland is available; native Wayland copies may be missed.
    XWaylandUnverified,
    /// COSMIC without `COSMIC_DATA_CONTROL_ENABLED=1`.
    CosmicDisabled,
    /// Wayland without `zwlr_foreign_toplevel_manager_v1`.
    NoForeignToplevel,
    /// Wayland has no way to intercept keys.
    WaylandNoIntercept,
    /// X11: `XGrabKey` interception is not part of 4b (phase-4.md §4.9.2).
    /// Not in the §4.9.4 table yet (proposed).
    X11NoIntercept,
    /// Neither `WAYLAND_DISPLAY` nor `DISPLAY` (or neither connects).
    /// Not in the §4.9.4 table yet (proposed).
    NoDisplay,
}

/// Mirrors `Capability` (phase-4.md §4.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    Active,
    Degraded(Reason),
    Unavailable(Reason),
}

/// Mirrors `ProtectionStatus` (phase-4.md §4.8.1) for the Linux backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxStatus {
    pub watch: Capability,
    pub write: Capability,
    pub foreground: Capability,
    pub intercept: Capability,
}

/// The outcome of [`select`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub backend: Backend,
    pub foreground: ForegroundSource,
    pub status: LinuxStatus,
}

/// Picks the backend (phase-4.md §4.9.2):
///
/// 1. `WAYLAND_DISPLAY` → ext data-control, else wlr data-control;
/// 2. neither, but `DISPLAY` → XWayland + XFixes, `Degraded(XWaylandUnverified)`;
/// 3. plain X11 → XFixes.
///
/// `globals` is `None` when there is no Wayland display or it could not be
/// reached; that case is treated like plain X11 when `DISPLAY` is set.
pub fn select(env: &Env, globals: Option<WaylandGlobals>) -> Selection {
    use Capability::{Active, Degraded, Unavailable};

    let wayland = env.wayland_display.is_some() && globals.is_some();
    let g = globals.unwrap_or_default();
    let has_x = env.x11_display.is_some();

    if !wayland {
        if has_x {
            return Selection {
                backend: Backend::X11,
                foreground: ForegroundSource::X11ActiveWindow,
                status: LinuxStatus {
                    watch: Active,
                    write: Active,
                    foreground: Active,
                    intercept: Unavailable(Reason::X11NoIntercept),
                },
            };
        }
        let none = Unavailable(Reason::NoDisplay);
        return Selection {
            backend: Backend::None,
            foreground: ForegroundSource::None,
            status: LinuxStatus {
                watch: none,
                write: none,
                foreground: none,
                intercept: none,
            },
        };
    }

    let (foreground_src, foreground) = if g.wlr_foreign_toplevel {
        (ForegroundSource::WlrForeignToplevel, Active)
    } else {
        (
            ForegroundSource::None,
            Unavailable(Reason::NoForeignToplevel),
        )
    };
    let intercept = Unavailable(Reason::WaylandNoIntercept);

    if g.seat && (g.ext_data_control || g.wlr_data_control) {
        let backend = if g.ext_data_control {
            Backend::WaylandExt
        } else {
            Backend::WaylandWlr
        };
        return Selection {
            backend,
            foreground: foreground_src,
            status: LinuxStatus {
                watch: Active,
                write: Active,
                foreground,
                intercept,
            },
        };
    }

    // No data-control. COSMIC hides it behind an opt-in variable; say so
    // even when the XWayland fallback runs, since that one is unverified.
    let missing = if env.is_cosmic() {
        Reason::CosmicDisabled
    } else {
        Reason::NoDataControl
    };
    if has_x {
        let watch = if missing == Reason::CosmicDisabled {
            Unavailable(missing)
        } else {
            Degraded(Reason::XWaylandUnverified)
        };
        return Selection {
            backend: Backend::XWayland,
            foreground: foreground_src,
            status: LinuxStatus {
                watch,
                write: Degraded(Reason::XWaylandUnverified),
                foreground,
                intercept,
            },
        };
    }
    Selection {
        backend: Backend::None,
        foreground: foreground_src,
        status: LinuxStatus {
            watch: Unavailable(missing),
            write: Unavailable(missing),
            foreground,
            intercept,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::Capability::{Active, Degraded, Unavailable};
    use super::*;

    fn env(wl: bool, x: bool, desktop: Option<&str>) -> Env {
        Env::from_vars(
            wl.then(|| "wayland-1".into()),
            x.then(|| ":0".into()),
            desktop.map(Into::into),
        )
    }

    fn globals(ext: bool, wlr: bool, toplevel: bool) -> Option<WaylandGlobals> {
        Some(WaylandGlobals {
            ext_data_control: ext,
            wlr_data_control: wlr,
            wlr_foreign_toplevel: toplevel,
            seat: true,
        })
    }

    #[test]
    fn ext_is_preferred_over_wlr() {
        let s = select(&env(true, true, None), globals(true, true, true));
        assert_eq!(s.backend, Backend::WaylandExt);
        assert_eq!(s.foreground, ForegroundSource::WlrForeignToplevel);
        assert_eq!(s.status.watch, Active);
        assert_eq!(s.status.foreground, Active);
        assert_eq!(s.status.intercept, Unavailable(Reason::WaylandNoIntercept));
    }

    #[test]
    fn wlr_only_compositor() {
        // sway 1.10 / Ubuntu 25.10 (S5 pitfall 2).
        let s = select(&env(true, false, None), globals(false, true, true));
        assert_eq!(s.backend, Backend::WaylandWlr);
        assert_eq!(s.status.write, Active);
    }

    #[test]
    fn kwin_without_foreign_toplevel() {
        let s = select(&env(true, true, Some("KDE")), globals(true, false, false));
        assert_eq!(s.backend, Backend::WaylandExt);
        assert_eq!(s.foreground, ForegroundSource::None);
        assert_eq!(s.status.foreground, Unavailable(Reason::NoForeignToplevel));
    }

    #[test]
    fn gnome_falls_back_to_xwayland_unverified() {
        let s = select(
            &env(true, true, Some("ubuntu:GNOME")),
            globals(false, false, false),
        );
        assert_eq!(s.backend, Backend::XWayland);
        assert_eq!(s.status.watch, Degraded(Reason::XWaylandUnverified));
        assert_eq!(s.status.foreground, Unavailable(Reason::NoForeignToplevel));
        assert_eq!(s.status.intercept, Unavailable(Reason::WaylandNoIntercept));
    }

    #[test]
    fn gnome_without_xwayland() {
        let s = select(
            &env(true, false, Some("GNOME")),
            globals(false, false, false),
        );
        assert_eq!(s.backend, Backend::None);
        assert_eq!(s.status.watch, Unavailable(Reason::NoDataControl));
        assert_eq!(s.status.write, Unavailable(Reason::NoDataControl));
    }

    #[test]
    fn cosmic_hint() {
        for x in [true, false] {
            let s = select(&env(true, x, Some("COSMIC")), globals(false, false, true));
            assert_eq!(s.status.watch, Unavailable(Reason::CosmicDisabled), "x={x}");
        }
        // With data-control enabled COSMIC is a normal compositor.
        let s = select(&env(true, true, Some("cosmic")), globals(true, true, true));
        assert_eq!(s.backend, Backend::WaylandExt);
        assert_eq!(s.status.watch, Active);
    }

    #[test]
    fn plain_x11() {
        let s = select(&env(false, true, None), None);
        assert_eq!(s.backend, Backend::X11);
        assert_eq!(s.foreground, ForegroundSource::X11ActiveWindow);
        assert_eq!(s.status.foreground, Active);
        assert_eq!(s.status.intercept, Unavailable(Reason::X11NoIntercept));
    }

    #[test]
    fn unreachable_wayland_with_display_is_x11() {
        let s = select(&env(true, true, None), None);
        assert_eq!(s.backend, Backend::X11);
    }

    #[test]
    fn no_seat_means_no_data_control() {
        let mut g = globals(true, true, false).unwrap();
        g.seat = false;
        let s = select(&env(true, true, None), Some(g));
        assert_eq!(s.backend, Backend::XWayland);
    }

    #[test]
    fn nothing_at_all() {
        let s = select(&env(false, false, None), None);
        assert_eq!(s.backend, Backend::None);
        assert_eq!(s.status.watch, Unavailable(Reason::NoDisplay));
    }

    #[test]
    fn wayland_socket_path() {
        let mut e = env(true, false, None);
        assert_eq!(
            e.wayland_socket(),
            None,
            "relative name needs XDG_RUNTIME_DIR"
        );
        e.runtime_dir = Some("/run/user/1000".into());
        assert_eq!(
            e.wayland_socket().as_deref(),
            Some(std::path::Path::new("/run/user/1000/wayland-1"))
        );
        e.wayland_display = Some("/tmp/sock".into());
        assert_eq!(
            e.wayland_socket().as_deref(),
            Some(std::path::Path::new("/tmp/sock"))
        );
    }

    #[test]
    fn empty_vars_are_unset() {
        let e = Env::from_vars(Some(" ".into()), Some(String::new()), None);
        assert_eq!(e, Env::default());
    }
}
