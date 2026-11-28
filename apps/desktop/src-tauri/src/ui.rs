//! The Tauri side of [`UiSink`]: events, notifications, tray, windows
//! (phase-4.md §4.3, §4.5, §4.8.1).
//!
//! Text for people is rendered here with Fluent (`locales/*/ui-desktop*.ftl`,
//! plus the core message files). Notifications go through
//! `tauri-plugin-notification`; restore is only offered from the tray (§4.5).

use std::sync::mpsc::{Sender, sync_channel};

use paste_warden_i18n::Localizer;
use paste_warden_platform::status::{ProtectionStatus, TrayState};
use tauri::image::Image;
use tauri::menu::{CheckMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Runtime, Theme, WebviewWindow, WebviewWindowBuilder};
use tauri_plugin_notification::NotificationExt;

use crate::model::{
    ConfirmPayload, Line, NavigatePayload, Notice, Section, SettingsPayload, StatusPayload, UiSink,
};
use crate::worker::{UiCommand, WorkerMsg};

pub const TRAY_ID: &str = "main";
pub const WINDOW_SETTINGS: &str = "settings";
pub const WINDOW_CONFIRM: &str = "confirm";
pub const WINDOW_ONBOARDING: &str = "onboarding";

pub const EVENT_STATUS: &str = "protection-status";
pub const EVENT_SETTINGS: &str = "settings-changed";
pub const EVENT_CONFIRM: &str = "paste-confirm";
/// Addition to the §4.3 contract: the tray asks the settings window to show a
/// section.
pub const EVENT_NAVIGATE: &str = "navigate";

/// Longest notification body / title (Windows toasts truncate anyway).
pub const NOTIFY_BODY_MAX_CHARS: usize = 400;
pub const NOTIFY_TITLE_MAX_CHARS: usize = 64;
/// Windows `NOTIFYICONDATA.szTip` holds 128 UTF-16 units.
pub const TRAY_TOOLTIP_MAX_CHARS: usize = 120;

/// Menu item ids.
mod item {
    pub const STATUS: &str = "status";
    pub const RESTORE: &str = "restore";
    pub const REGISTER: &str = "register-secret";
    pub const MANAGE: &str = "manage-secrets";
    pub const STRICT_REGISTERED: &str = "strict-registered";
    pub const STRICT_DETECTED: &str = "strict-detected";
    pub const ALLOWLIST: &str = "allowlist";
    pub const SETTINGS: &str = "settings";
    pub const QUIT: &str = "quit";
}

/// The worker's sender, managed by Tauri.
pub struct WorkerTx(pub Sender<WorkerMsg>);

impl WorkerTx {
    pub fn send(&self, cmd: UiCommand) -> bool {
        self.0.send(WorkerMsg::Ui(cmd)).is_ok()
    }
}

/// Renders one notification line.
pub fn render(loc: &Localizer, line: &Line) -> String {
    match line {
        Line::Msg(m) => loc.format(m),
        Line::Masked(s) => s.clone(),
        Line::Nested(m, nested) => {
            let mut m = m.clone();
            for (k, n) in nested {
                m = m.arg(k, loc.format(n));
            }
            loc.format(&m)
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Renders a notice as (title, body).
pub fn render_notice(loc: &Localizer, n: &Notice) -> (String, String) {
    let title = clip(&render(loc, &n.title), NOTIFY_TITLE_MAX_CHARS);
    let body: Vec<String> = n.body.iter().map(|l| render(loc, l)).collect();
    (title, clip(&body.join("\n"), NOTIFY_BODY_MAX_CHARS))
}

/// Tray tooltip: the app name, then one line per degraded area.
pub fn tooltip(loc: &Localizer, status: &ProtectionStatus) -> String {
    let mut lines = vec![loc.format(&paste_warden_core::Message::new("ui-app-name"))];
    for r in status.tooltip_reasons() {
        let id = r.message_id();
        lines.push(loc.format(&paste_warden_core::Message {
            id: id.into(),
            args: Vec::new(),
        }));
    }
    clip(&lines.join("\n"), TRAY_TOOLTIP_MAX_CHARS)
}

fn tray_icon(state: TrayState) -> Image<'static> {
    match state {
        TrayState::Normal => tauri::include_image!("icons/tray/normal.png"),
        TrayState::Degraded => tauri::include_image!("icons/tray/degraded.png"),
        TrayState::Failed => tauri::include_image!("icons/tray/failed.png"),
    }
}

fn tray_status_id(state: TrayState) -> &'static str {
    match state {
        TrayState::Normal => "ui-desktop-tray-status-normal",
        TrayState::Degraded => "ui-desktop-tray-status-degraded",
        TrayState::Failed => "ui-desktop-tray-status-failed",
    }
}

fn t(loc: &Localizer, id: &'static str) -> String {
    loc.format(&paste_warden_core::Message::new(id))
}

/// Legacy tray menu (`TrayApp.cs`) plus a status line and "settings".
fn build_menu<R: Runtime>(
    app: &AppHandle<R>,
    loc: &Localizer,
    state: TrayState,
    restore: bool,
    settings: Option<&SettingsPayload>,
) -> tauri::Result<Menu<R>> {
    let (registered, detected) = settings.map_or((true, false), |s| {
        (s.paste_guard.registered, s.paste_guard.detected)
    });
    let status = MenuItem::with_id(
        app,
        item::STATUS,
        t(loc, tray_status_id(state)),
        false,
        None::<&str>,
    )?;
    let restore = MenuItem::with_id(
        app,
        item::RESTORE,
        t(loc, "ui-desktop-tray-restore"),
        restore,
        None::<&str>,
    )?;
    let register = MenuItem::with_id(
        app,
        item::REGISTER,
        t(loc, "ui-desktop-tray-register-secret"),
        true,
        None::<&str>,
    )?;
    let manage = MenuItem::with_id(
        app,
        item::MANAGE,
        t(loc, "ui-desktop-tray-manage-secrets"),
        true,
        None::<&str>,
    )?;
    let strict_registered = CheckMenuItem::with_id(
        app,
        item::STRICT_REGISTERED,
        t(loc, "ui-desktop-tray-strict-registered"),
        true,
        registered,
        None::<&str>,
    )?;
    let strict_detected = CheckMenuItem::with_id(
        app,
        item::STRICT_DETECTED,
        t(loc, "ui-desktop-tray-strict-detected"),
        true,
        detected,
        None::<&str>,
    )?;
    let allowlist = MenuItem::with_id(
        app,
        item::ALLOWLIST,
        t(loc, "ui-desktop-tray-allowlist"),
        true,
        None::<&str>,
    )?;
    let paste_menu = Submenu::with_items(
        app,
        t(loc, "ui-desktop-tray-paste-menu"),
        true,
        &[
            &strict_registered,
            &strict_detected,
            &PredefinedMenuItem::separator(app)?,
            &allowlist,
        ],
    )?;
    let settings = MenuItem::with_id(
        app,
        item::SETTINGS,
        t(loc, "ui-desktop-tray-settings"),
        true,
        None::<&str>,
    )?;
    let quit = MenuItem::with_id(
        app,
        item::QUIT,
        t(loc, "ui-desktop-tray-quit"),
        true,
        None::<&str>,
    )?;
    Menu::with_items(
        app,
        &[
            &status,
            &PredefinedMenuItem::separator(app)?,
            &restore,
            &register,
            &manage,
            &paste_menu,
            &PredefinedMenuItem::separator(app)?,
            &settings,
            &quit,
        ],
    )
}

/// Creates the tray icon and wires its menu to the worker.
pub fn create_tray<R: Runtime>(app: &AppHandle<R>, loc: &Localizer) -> tauri::Result<TrayIcon<R>> {
    let menu = build_menu(app, loc, TrayState::Normal, false, None)?;
    TrayIconBuilder::with_id(TRAY_ID)
        .icon(tray_icon(TrayState::Normal))
        .tooltip(t(loc, "ui-app-name"))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| on_menu(app, event.id().as_ref()))
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                open_settings(tray.app_handle(), None);
            }
        })
        .build(app)
}

fn on_menu<R: Runtime>(app: &AppHandle<R>, id: &str) {
    let tx = app.state::<WorkerTx>();
    match id {
        item::RESTORE => {
            let (reply, _rx) = sync_channel(1);
            tx.send(UiCommand::Restore(reply));
        }
        item::REGISTER => open_settings(app, Some(Section::RegisterSecret)),
        item::MANAGE => open_settings(app, Some(Section::Secrets)),
        item::ALLOWLIST => open_settings(app, Some(Section::Allowlist)),
        item::SETTINGS => open_settings(app, Some(Section::General)),
        item::STRICT_REGISTERED => {
            tx.send(UiCommand::TogglePasteGuard { registered: true });
        }
        item::STRICT_DETECTED => {
            tx.send(UiCommand::TogglePasteGuard { registered: false });
        }
        item::QUIT => crate::app::quit(app),
        _ => {}
    }
}

/// Shows (creating on first use) a window declared in `tauri.conf.json`.
pub fn show_window<R: Runtime>(app: &AppHandle<R>, label: &str) -> Option<WebviewWindow<R>> {
    let w = match app.get_webview_window(label) {
        Some(w) => w,
        None => {
            let cfg = app
                .config()
                .app
                .windows
                .iter()
                .find(|w| w.label == label)?
                .clone();
            WebviewWindowBuilder::from_config(app, &cfg)
                .ok()?
                .build()
                .ok()?
        }
    };
    let _ = w.unminimize();
    let _ = w.show();
    let _ = w.set_focus();
    Some(w)
}

/// Opens the settings window on the main thread (window creation off the
/// main thread can deadlock on Windows).
pub fn open_settings<R: Runtime>(app: &AppHandle<R>, section: Option<Section>) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if show_window(&handle, WINDOW_SETTINGS).is_some()
            && let Some(section) = section
        {
            let _ = handle.emit_to(WINDOW_SETTINGS, EVENT_NAVIGATE, NavigatePayload { section });
        }
    });
}

fn theme_of(id: &str) -> Option<Theme> {
    match id {
        "light" => Some(Theme::Light),
        "dark" => Some(Theme::Dark),
        _ => None,
    }
}

/// [`UiSink`] backed by an [`AppHandle`]. Lives on `pw-work`.
pub struct TauriUi<R: Runtime> {
    app: AppHandle<R>,
    system_locale: &'static str,
    locale: &'static str,
    status: ProtectionStatus,
    restore: bool,
    settings: Option<SettingsPayload>,
}

impl<R: Runtime> TauriUi<R> {
    pub fn new(app: AppHandle<R>, system_locale: &'static str) -> Self {
        TauriUi {
            app,
            system_locale,
            locale: system_locale,
            status: ProtectionStatus::default(),
            restore: false,
            settings: None,
        }
    }

    fn loc(&self) -> &'static Localizer {
        paste_warden_report::localizer(self.locale)
    }

    fn refresh_tray(&self) {
        let Some(tray) = self.app.tray_by_id(TRAY_ID) else {
            return;
        };
        let state = self.status.tray_state();
        let loc = self.loc();
        let _ = tray.set_icon(Some(tray_icon(state)));
        // Not supported on Linux; the status line in the menu covers it.
        let _ = tray.set_tooltip(Some(tooltip(loc, &self.status)));
        if let Ok(menu) = build_menu(&self.app, loc, state, self.restore, self.settings.as_ref()) {
            let _ = tray.set_menu(Some(menu));
        }
    }
}

impl<R: Runtime> UiSink for TauriUi<R> {
    fn status_changed(&mut self, status: &ProtectionStatus) {
        self.status = *status;
        let _ = self.app.emit(EVENT_STATUS, StatusPayload::from(status));
        self.refresh_tray();
    }

    fn settings_changed(&mut self, settings: &SettingsPayload) {
        self.locale = match settings.locale {
            "zh-TW" => "zh-TW",
            "en" => "en",
            _ => self.system_locale,
        };
        let theme = theme_of(settings.theme);
        for w in self.app.webview_windows().values() {
            let _ = w.set_theme(theme);
        }
        self.settings = Some(settings.clone());
        let _ = self.app.emit(EVENT_SETTINGS, settings);
        self.refresh_tray();
    }

    fn notify(&mut self, notice: &Notice) {
        let (title, body) = render_notice(self.loc(), notice);
        let _ = self
            .app
            .notification()
            .builder()
            .title(title)
            .body(body)
            .show();
    }

    fn open_confirm(&mut self, payload: &ConfirmPayload) {
        let app = self.app.clone();
        let payload = payload.clone();
        let _ = self.app.run_on_main_thread(move || {
            if let Some(w) = show_window(&app, WINDOW_CONFIRM) {
                let _ = w.set_always_on_top(true);
                let _ = w.center();
            }
            let _ = app.emit_to(WINDOW_CONFIRM, EVENT_CONFIRM, payload);
        });
    }

    fn close_confirm(&mut self) {
        if let Some(w) = self.app.get_webview_window(WINDOW_CONFIRM) {
            let _ = w.hide();
        }
    }

    fn restore_available(&mut self, available: bool) {
        if self.restore != available {
            self.restore = available;
            self.refresh_tray();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paste_warden_core::Message;
    use paste_warden_core::policy::throttle::NotificationLevel;
    use paste_warden_platform::status::{Capability, Reason};

    #[test]
    fn nested_lines_render_inner_messages_first() {
        let loc = Localizer::new("en");
        let line = Line::Nested(
            Message::new("ui-desktop-toast-elevated-unprotected"),
            vec![("kind", Message::new("registered-untitled"))],
        );
        let s = render(&loc, &line);
        assert!(!s.contains("ui-desktop"), "{s}");
        assert!(s.contains(&loc.format(&Message::new("registered-untitled"))));
    }

    #[test]
    fn notice_is_clipped() {
        let loc = Localizer::new("en");
        let n = Notice {
            level: NotificationLevel::Warning,
            title: Line::Masked("t".repeat(200)),
            body: vec![Line::Masked("b".repeat(1_000))],
        };
        let (t, b) = render_notice(&loc, &n);
        assert_eq!(t.chars().count(), NOTIFY_TITLE_MAX_CHARS);
        assert_eq!(b.chars().count(), NOTIFY_BODY_MAX_CHARS);
    }

    #[test]
    fn tooltip_lists_reasons() {
        let loc = Localizer::new("en");
        let s = ProtectionStatus {
            intercept: Capability::Degraded(Reason::ElevatedForeground),
            ..Default::default()
        };
        let tip = tooltip(&loc, &s);
        assert_eq!(tip.lines().count(), 2);
        assert!(tip.chars().count() <= TRAY_TOOLTIP_MAX_CHARS);
    }
}
