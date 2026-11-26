//! Live CSS theming for Lily Vault.
//!
//! Reads `~/.config/theme-switch/current.conf` if present (and watches it live),
//! falling back to a dark rose/lavender palette on machines without theme-switch.

use gtk4::gdk;
use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::CssProvider;
use std::collections::HashMap;
use std::fs;
use std::rc::Rc;

fn hex_to_rgba(hex: &str, alpha: f64) -> String {
    let clean = hex.trim().trim_start_matches('#');
    if clean.len() == 6 {
        if let (Ok(r), Ok(g), Ok(b)) = (
            u8::from_str_radix(&clean[0..2], 16),
            u8::from_str_radix(&clean[2..4], 16),
            u8::from_str_radix(&clean[4..6], 16),
        ) {
            return format!("rgba({}, {}, {}, {:.2})", r, g, b, alpha);
        }
    }
    format!("rgba(30, 30, 46, {:.2})", alpha)
}

fn load_palette() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut path = glib::user_config_dir();
    path.push("theme-switch");
    path.push("current.conf");

    if let Ok(content) = fs::read_to_string(&path) {
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = trimmed.split_once('=') {
                let key = k.trim().to_string();
                let val = v.trim().trim_matches('"').trim_start_matches('#').to_string();
                map.insert(key, val);
            }
        }
    }
    map
}

pub fn init_theme() {
    let display = gdk::Display::default().expect("Could not connect to a display.");
    let provider = CssProvider::new();
    gtk4::style_context_add_provider_for_display(
        &display,
        &provider,
        gtk4::STYLE_PROVIDER_PRIORITY_APPLICATION,
    );

    let scrollbar_provider = CssProvider::new();
    gtk4::style_context_add_provider_for_display(
        &display,
        &scrollbar_provider,
        gtk4::STYLE_PROVIDER_PRIORITY_USER + 1,
    );

    let update_css: Rc<dyn Fn()> = {
        let provider = provider.clone();
        let sb_provider = scrollbar_provider.clone();
        Rc::new(move || {
            let p = load_palette();
            let get = |k: &str, fb: &str| p.get(k).map(|s| s.as_str()).unwrap_or(fb).to_string();

            let bg_main = get("BG_MAIN", "1c1522");
            let bg_recessed = get("BG_RECESSED", "140e19");
            let bg_contrast = get("BG_CONTRAST", "241b2c");
            let fg_main = get("FG_MAIN", "f5e9f7");
            let fg_muted = get("FG_MUTED", "a896b0");
            let accent1 = get("ACCENT1", "c77dbb");
            let accent2 = get("ACCENT2", "f2a6df");

            let bg_main_glass = hex_to_rgba(&bg_main, 0.72);
            let bg_recessed_glass = hex_to_rgba(&bg_recessed, 0.58);
            let bg_contrast_glass = hex_to_rgba(&bg_contrast, 0.68);
            let accent1_15 = hex_to_rgba(&accent1, 0.15);
            let accent1_24 = hex_to_rgba(&accent1, 0.24);
            let accent1_38 = hex_to_rgba(&accent1, 0.38);
            let accent1_55 = hex_to_rgba(&accent1, 0.55);
            let accent2_28 = hex_to_rgba(&accent2, 0.28);
            let accent2_70 = hex_to_rgba(&accent2, 0.70);
            let fg_main_06 = hex_to_rgba(&fg_main, 0.06);
            let fg_main_08 = hex_to_rgba(&fg_main, 0.08);
            let fg_main_15 = hex_to_rgba(&fg_main, 0.15);

            let css = format!(
                r#"
                window.vault-window {{ background-color: {bg_main_glass}; color: #{fg_main}; }}
                .vault-topbar {{ background-color: {bg_recessed_glass}; border-bottom: 1px solid {accent1_38}; padding: 10px 14px; }}
                .vault-card {{ background-color: {bg_recessed_glass}; border: 1px solid {accent1_38}; border-radius: 12px; padding: 16px; }}
                .vault-title {{ color: #{accent2}; font-family: 'Josefin Sans', sans-serif; font-size: 20px; font-weight: bold; }}
                .vault-subtitle {{ color: #{fg_muted}; font-family: 'Josefin Sans', sans-serif; font-size: 13px; }}
                .vault-section-hdr {{ color: #{accent2}; font-family: 'MesloLGL Nerd Font', monospace; font-size: 12px; font-weight: bold; letter-spacing: 1px; }}
                .vault-badge {{ color: #{accent2}; font-family: 'MesloLGL Nerd Font', monospace; font-size: 12px; font-weight: bold; }}
                .vault-muted {{ color: #{fg_muted}; font-family: 'Josefin Sans', sans-serif; font-size: 12px; }}
                .vault-err {{ color: #f38ba8; font-family: 'Josefin Sans', sans-serif; font-size: 13px; font-weight: bold; }}
                .vault-ok {{ color: #a6e3a1; font-family: 'Josefin Sans', sans-serif; font-size: 13px; font-weight: bold; }}

                .vault-entry {{ background-color: {bg_contrast_glass}; border: 1px solid transparent; border-radius: 9px; color: #{fg_main}; font-family: 'Josefin Sans', sans-serif; padding: 7px 12px; }}
                .vault-entry:focus {{ border-color: {accent1_55}; }}

                .vault-btn {{ background-color: {fg_main_08}; border: 1px solid transparent; border-radius: 9px; padding: 7px 13px; color: #{fg_main}; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-weight: bold; box-shadow: none; transition: background-color 0.15s ease; }}
                .vault-btn label {{ color: #{fg_main}; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-size: 13px; font-weight: bold; }}
                .vault-btn:hover {{ background-color: {fg_main_15}; }}
                .vault-btn.active {{ background-color: {accent1_24}; }}
                .vault-btn.active label {{ color: #{accent2}; }}
                .vault-btn.active:hover {{ background-color: {accent1_38}; }}

                .vault-primary-btn {{ background-color: {accent1_24}; border: 1px solid transparent; border-radius: 9px; padding: 8px 16px; color: #{accent2}; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-weight: bold; box-shadow: none; transition: background-color 0.15s ease; }}
                .vault-primary-btn label {{ color: #{accent2}; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-size: 14px; font-weight: bold; }}
                .vault-primary-btn:hover {{ background-color: {accent1_38}; }}
                .vault-primary-btn:hover label {{ color: #{fg_main}; }}

                .vault-danger-btn {{ background-color: rgba(243, 139, 168, 0.14); border: 1px solid transparent; border-radius: 9px; padding: 7px 13px; color: #f38ba8; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-weight: bold; box-shadow: none; transition: background-color 0.15s ease; }}
                .vault-danger-btn label {{ color: #f38ba8; font-family: 'Josefin Sans', 'MesloLGL Nerd Font', sans-serif; font-size: 13px; font-weight: bold; }}
                .vault-danger-btn:hover {{ background-color: rgba(243, 139, 168, 0.28); }}

                .vault-row-btn {{ background-color: transparent; border: none; border-radius: 10px; padding: 8px 10px; box-shadow: none; transition: background-color 0.15s ease; }}
                .vault-row-btn:hover {{ background-color: {accent1_15}; }}
                .vault-row-btn label {{ color: #{fg_main}; font-family: 'Josefin Sans', sans-serif; font-size: 14px; }}

                .vault-chip {{ background-color: {fg_main_06}; border: 1px solid transparent; border-radius: 8px; padding: 4px 10px; box-shadow: none; }}
                .vault-chip label {{ color: #{fg_muted}; font-family: 'MesloLGL Nerd Font', monospace; font-size: 11px; }}
                .vault-chip:hover {{ background-color: {fg_main_15}; }}
                .vault-chip:hover label {{ color: #{fg_main}; }}

                popover.vault-popover > contents {{ background-color: #{bg_recessed}; border: 1px solid {accent1_55}; border-radius: 10px; padding: 6px; }}
                progressbar.vault-cap > trough {{ background-color: {fg_main_08}; border: none; border-radius: 6px; min-height: 8px; }}
                progressbar.vault-cap > trough > progress {{ background-color: #{accent2}; border-radius: 6px; min-height: 8px; }}
                "#
            );
            provider.load_from_data(&css);

            let sb_css = format!(
                r#"
                scrolledwindow > scrollbar, scrolledwindow > scrollbar > range, scrolledwindow > scrollbar > range > trough,
                scrollbar, scrollbar > range, scrollbar > range > trough {{ background-color: transparent; border: none; margin: 0px; padding: 0px; min-width: 0px; min-height: 0px; box-shadow: none; }}
                scrolledwindow > scrollbar.vertical > range > trough > slider,
                scrollbar.vertical.overlay-indicator:not(.dragging):not(.hovering) > range > trough > slider,
                scrollbar.vertical > range > trough > slider {{ min-width: 2px; min-height: 24px; margin: 2px 0px; padding: 0px; border: none; border-radius: 99px; background-color: {accent2_28}; box-shadow: none; }}
                scrolledwindow > scrollbar.vertical:hover > range > trough > slider,
                scrollbar.vertical:hover > range > trough > slider,
                scrollbar.vertical > range > trough > slider:hover,
                scrollbar.vertical > range > trough > slider:active {{ min-width: 4px; background-color: {accent2_70}; }}
                "#
            );
            sb_provider.load_from_data(&sb_css);
        })
    };

    update_css();

    let mut watch_path = glib::user_config_dir();
    watch_path.push("theme-switch");
    watch_path.push("current.conf");
    let file = gio::File::for_path(&watch_path);
    if let Ok(monitor) = file.monitor_file(gio::FileMonitorFlags::NONE, gio::Cancellable::NONE) {
        let cb = update_css.clone();
        monitor.connect_changed(move |_, _, _, event| {
            if event == gio::FileMonitorEvent::ChangesDoneHint
                || event == gio::FileMonitorEvent::Created
            {
                cb();
            }
        });
        std::boxed::Box::leak(std::boxed::Box::new(monitor));
    }
}
