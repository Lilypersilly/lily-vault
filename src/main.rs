//! Lily Vault — Standalone encrypted `.lilar` file & password vault desktop app.
//!
//! 100% compatible with Lily Dashboard's Locker vaults (`vault.lilar` + `block_*.lilar`).
//! Point to any vault folder, unlock via auto-detected USB `.lily_master.key` OR any
//! keyfile on disk, preview files in RAM (`/dev/shm/lily-vault`), and manage encrypted
//! vault passwords strictly in RAM with volatile zeroization on lock or exit.

mod passwords;
mod theme;
mod vault;

use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Align, Application, ApplicationWindow, Box, Button, Entry, FileChooserAction,
    FileChooserNative, GestureClick, Label, Orientation, PolicyType, Popover, ProgressBar,
    ResponseType, ScrolledWindow, SearchEntry, Stack,
};
use std::cell::{Cell, RefCell};
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::mpsc;
use std::time::Duration;
use vault::{UnlockedSession, VaultAppConfig, WorkerEvent, CHUNK_SIZE, INDEX_FILENAME, KEYFILE_NAME, RAM_EXTRACT_DIR, TAG_SIZE};

const APP_ID: &str = "com.lily.vault";

fn main() {
    // GTK 4.24 sends an empty `ext_background_effect_manager_v1` blur region on Wayland,
    // which overrides Hyprland's native GPU blur. Disabling it restores frosted glass blur.
    let existing = std::env::var("GDK_WAYLAND_DISABLE").unwrap_or_default();
    if !existing.contains("ext_background_effect_manager_v1") {
        let new_val = if existing.is_empty() {
            "ext_background_effect_manager_v1".to_string()
        } else {
            format!("{},ext_background_effect_manager_v1", existing)
        };
        std::env::set_var("GDK_WAYLAND_DISABLE", new_val);
    }

    let app = Application::builder().application_id(APP_ID).build();
    app.connect_startup(|_| {
        theme::init_theme();
    });
    app.connect_activate(|app| {
        if let Some(win) = app.active_window() {
            win.present();
            return;
        }
        build_ui(app);
    });
    app.run();
}

fn build_ui(app: &Application) {
    let window = ApplicationWindow::builder()
        .application(app)
        .title("Lily Vault")
        .default_width(780)
        .default_height(580)
        .css_classes(vec!["vault-window".to_string()])
        .build();

    let main_stack = Stack::new();
    main_stack.set_hhomogeneous(false);
    main_stack.set_hexpand(true);
    main_stack.set_vexpand(true);
    window.set_child(Some(&main_stack));

    let cfg_rc: Rc<RefCell<VaultAppConfig>> = Rc::new(RefCell::new(vault::load_app_config()));
    let session_rc: Rc<RefCell<Option<UnlockedSession>>> = Rc::new(RefCell::new(None));
    let active_dialog: Rc<RefCell<Option<FileChooserNative>>> = Rc::new(RefCell::new(None));
    let (tx, rx) = mpsc::channel::<WorkerEvent>();

    // =========================================================================
    // VIEW 1: OPEN / UNLOCK VAULT SCREEN
    // =========================================================================
    let unlock_outer = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(14)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(32)
        .margin_end(32)
        .valign(Align::Center)
        .halign(Align::Center)
        .width_request(540)
        .build();

    let header_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(10)
        .build();
    let app_title = Label::builder()
        .label("󰌾 Lily Vault")
        .halign(Align::Start)
        .hexpand(true)
        .css_classes(vec!["vault-title".to_string()])
        .build();
    let goto_create_btn = Button::builder()
        .label("+ Create New Vault")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    header_row.append(&app_title);
    header_row.append(&goto_create_btn);
    unlock_outer.append(&header_row);

    // Card 1: Vault Folder Picker
    let folder_card = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(8)
        .css_classes(vec!["vault-card".to_string()])
        .build();
    folder_card.append(
        &Label::builder()
            .label("VAULT FOLDER")
            .halign(Align::Start)
            .css_classes(vec!["vault-section-hdr".to_string()])
            .build(),
    );

    let folder_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    let vault_dir_entry = Entry::builder()
        .placeholder_text("Select folder containing vault.lilar...")
        .text(&cfg_rc.borrow().last_vault_dir)
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let browse_vault_btn = Button::builder()
        .label("󰉋 Browse")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    folder_row.append(&vault_dir_entry);
    folder_row.append(&browse_vault_btn);
    folder_card.append(&folder_row);

    let vault_status_lbl = Label::builder()
        .label("")
        .halign(Align::Start)
        .css_classes(vec!["vault-muted".to_string()])
        .build();
    folder_card.append(&vault_status_lbl);

    let recent_box = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();
    folder_card.append(&recent_box);
    unlock_outer.append(&folder_card);

    // Card 2: Key Source (USB Auto-Detect OR Keyfile on Disk)
    let key_card = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(10)
        .css_classes(vec!["vault-card".to_string()])
        .build();
    key_card.append(
        &Label::builder()
            .label("MASTER KEY SOURCE")
            .halign(Align::Start)
            .css_classes(vec!["vault-section-hdr".to_string()])
            .build(),
    );

    let key_mode_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    let use_file_mode = Rc::new(Cell::new(cfg_rc.borrow().key_mode == "file"));
    let usb_mode_btn = Button::builder()
        .label("󰕓 USB Auto-Detect")
        .css_classes(vec!["vault-btn".to_string()])
        .hexpand(true)
        .build();
    let file_mode_btn = Button::builder()
        .label("󰈔 Keyfile on Disk")
        .css_classes(vec!["vault-btn".to_string()])
        .hexpand(true)
        .build();
    key_mode_row.append(&usb_mode_btn);
    key_mode_row.append(&file_mode_btn);
    key_card.append(&key_mode_row);

    // USB status panel
    let usb_panel = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    let usb_status_lbl = Label::builder()
        .label("Scanning USB mounts...")
        .halign(Align::Start)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::Middle)
        .css_classes(vec!["vault-muted".to_string()])
        .build();
    let usb_rescan_btn = Button::builder()
        .label("󰑐 Rescan")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    usb_panel.append(&usb_status_lbl);
    usb_panel.append(&usb_rescan_btn);
    key_card.append(&usb_panel);

    // File picker panel
    let file_panel = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .visible(false)
        .build();
    let keyfile_entry = Entry::builder()
        .placeholder_text("Path to .lily_master.key (or any keyfile)...")
        .text(&cfg_rc.borrow().last_keyfile)
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let browse_key_btn = Button::builder()
        .label("󰈔 Pick Keyfile")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    file_panel.append(&keyfile_entry);
    file_panel.append(&browse_key_btn);
    key_card.append(&file_panel);

    // PIN entry + Unlock button
    let unlock_action_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .margin_top(4)
        .build();
    let unlock_pin_entry = Entry::builder()
        .placeholder_text("Enter Vault PIN...")
        .visibility(false)
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let unlock_btn = Button::builder()
        .label("󰌿 Unlock Vault")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .build();
    unlock_action_row.append(&unlock_pin_entry);
    unlock_action_row.append(&unlock_btn);
    key_card.append(&unlock_action_row);

    let unlock_err_lbl = Label::builder()
        .label("")
        .halign(Align::Start)
        .css_classes(vec!["vault-err".to_string()])
        .visible(false)
        .build();
    key_card.append(&unlock_err_lbl);
    unlock_outer.append(&key_card);

    main_stack.add_named(&unlock_outer, Some("unlock"));

    // =========================================================================
    // VIEW 2: CREATE NEW VAULT SCREEN
    // =========================================================================
    let create_outer = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(12)
        .margin_top(24)
        .margin_bottom(24)
        .margin_start(32)
        .margin_end(32)
        .valign(Align::Center)
        .halign(Align::Center)
        .width_request(540)
        .build();

    let create_hdr = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    create_hdr.append(
        &Label::builder()
            .label("Create New .lilar Vault")
            .halign(Align::Start)
            .hexpand(true)
            .css_classes(vec!["vault-title".to_string()])
            .build(),
    );
    let back_to_unlock_btn = Button::builder()
        .label("← Back")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    create_hdr.append(&back_to_unlock_btn);
    create_outer.append(&create_hdr);

    let create_card = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(10)
        .css_classes(vec!["vault-card".to_string()])
        .build();

    create_card.append(
        &Label::builder()
            .label("1. VAULT STORAGE FOLDER")
            .halign(Align::Start)
            .css_classes(vec!["vault-section-hdr".to_string()])
            .build(),
    );
    let c_dir_row = Box::builder().orientation(Orientation::Horizontal).spacing(8).build();
    let c_vault_entry = Entry::builder()
        .placeholder_text("Folder to store vault.lilar & block_*.lilar...")
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let c_vault_btn = Button::builder()
        .label("󰉋 Browse")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    c_dir_row.append(&c_vault_entry);
    c_dir_row.append(&c_vault_btn);
    create_card.append(&c_dir_row);

    create_card.append(
        &Label::builder()
            .label("2. MASTER KEYFILE LOCATION (USB OR FILE)")
            .halign(Align::Start)
            .css_classes(vec!["vault-section-hdr".to_string()])
            .margin_top(4)
            .build(),
    );
    let c_key_row = Box::builder().orientation(Orientation::Horizontal).spacing(8).build();
    let c_key_entry = Entry::builder()
        .placeholder_text("Where to save (or reuse) .lily_master.key...")
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let c_key_usb_btn = Button::builder()
        .label("󰕓 Use USB")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    let c_key_file_btn = Button::builder()
        .label("󰈔 Choose File")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    c_key_row.append(&c_key_entry);
    c_key_row.append(&c_key_usb_btn);
    c_key_row.append(&c_key_file_btn);
    create_card.append(&c_key_row);

    create_card.append(
        &Label::builder()
            .label("3. OPTIONAL PIN & SOFT SIZE LIMIT")
            .halign(Align::Start)
            .css_classes(vec!["vault-section-hdr".to_string()])
            .margin_top(4)
            .build(),
    );
    let c_opts_row = Box::builder().orientation(Orientation::Horizontal).spacing(8).build();
    let c_pin_entry = Entry::builder()
        .placeholder_text("Optional PIN (leave blank for keyfile-only)")
        .visibility(false)
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();
    let c_size_entry = Entry::builder()
        .text("50")
        .width_chars(6)
        .css_classes(vec!["vault-entry".to_string()])
        .tooltip_text("Soft capacity limit in GB")
        .build();
    c_opts_row.append(&c_pin_entry);
    c_opts_row.append(&c_size_entry);
    c_opts_row.append(
        &Label::builder()
            .label("GB")
            .css_classes(vec!["vault-muted".to_string()])
            .build(),
    );
    create_card.append(&c_opts_row);

    let create_err_lbl = Label::builder()
        .label("")
        .halign(Align::Start)
        .css_classes(vec!["vault-err".to_string()])
        .visible(false)
        .build();
    create_card.append(&create_err_lbl);

    let create_submit_btn = Button::builder()
        .label("󰌿 Create & Unlock Vault")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .margin_top(4)
        .build();
    create_card.append(&create_submit_btn);

    create_outer.append(&create_card);
    main_stack.add_named(&create_outer, Some("create"));

    // =========================================================================
    // VIEW 3: UNLOCKED VAULT WORKSPACE (FILES + PASSWORDS)
    // =========================================================================
    let vault_root = Box::builder()
        .orientation(Orientation::Vertical)
        .hexpand(true)
        .vexpand(true)
        .build();

    let topbar = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .css_classes(vec!["vault-topbar".to_string()])
        .build();

    let tab_files_btn = Button::builder()
        .label("󰉋 Files")
        .css_classes(vec!["vault-btn".to_string(), "active".to_string()])
        .build();
    let tab_pass_btn = Button::builder()
        .label("󰌾 Passwords")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    let active_vault_lbl = Label::builder()
        .label("")
        .halign(Align::Center)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::Middle)
        .css_classes(vec!["vault-muted".to_string()])
        .build();
    let lock_btn = Button::builder()
        .label("󰌾 Lock")
        .css_classes(vec!["vault-danger-btn".to_string()])
        .build();

    topbar.append(&tab_files_btn);
    topbar.append(&tab_pass_btn);
    topbar.append(&active_vault_lbl);
    topbar.append(&lock_btn);
    vault_root.append(&topbar);

    let inner_stack = Stack::new();
    inner_stack.set_hexpand(true);
    inner_stack.set_vexpand(true);
    vault_root.append(&inner_stack);

    // --- FILES TAB ---
    let files_page = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(10)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(14)
        .margin_end(14)
        .hexpand(true)
        .vexpand(true)
        .build();

    let cap_header = Box::builder().orientation(Orientation::Horizontal).spacing(8).build();
    let cap_lbl = Label::builder()
        .label("0 B / 50 GB")
        .halign(Align::Start)
        .hexpand(true)
        .css_classes(vec!["vault-badge".to_string()])
        .build();
    let edit_cap_btn = Button::builder()
        .label("Limit")
        .css_classes(vec!["vault-chip".to_string()])
        .tooltip_text("Change soft capacity limit (GB)")
        .build();
    cap_header.append(&cap_lbl);
    cap_header.append(&edit_cap_btn);

    let cap_edit_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .visible(false)
        .build();
    let cap_edit_entry = Entry::builder()
        .width_chars(6)
        .css_classes(vec!["vault-entry".to_string()])
        .build();
    let cap_save_btn = Button::builder()
        .label("Save GB")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .build();
    let cap_cancel_btn = Button::builder()
        .label("Cancel")
        .css_classes(vec!["vault-btn".to_string()])
        .build();
    cap_edit_row.append(&cap_edit_entry);
    cap_edit_row.append(&cap_save_btn);
    cap_edit_row.append(&cap_cancel_btn);

    let cap_bar = ProgressBar::builder()
        .css_classes(vec!["vault-cap".to_string()])
        .build();

    let file_search = SearchEntry::builder()
        .placeholder_text("Search vault files...")
        .css_classes(vec!["vault-entry".to_string()])
        .build();
    let file_query = Rc::new(RefCell::new(String::new()));

    let files_scroll = ScrolledWindow::builder()
        .hscrollbar_policy(PolicyType::Never)
        .vscrollbar_policy(PolicyType::Automatic)
        .vexpand(true)
        .hexpand(true)
        .build();
    let files_list = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();
    files_scroll.set_child(Some(&files_list));

    let files_footer = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(8)
        .build();
    let add_file_btn = Button::builder()
        .label("+ Add File")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .build();
    let vacuum_btn = Button::builder()
        .label("󰃢 Vacuum")
        .css_classes(vec!["vault-btn".to_string()])
        .tooltip_text("Reclaim dead space from replaced/deleted files")
        .build();
    let status_bar_lbl = Label::builder()
        .label("Ready.")
        .halign(Align::End)
        .hexpand(true)
        .ellipsize(gtk4::pango::EllipsizeMode::End)
        .css_classes(vec!["vault-muted".to_string()])
        .build();

    files_footer.append(&add_file_btn);
    files_footer.append(&vacuum_btn);
    files_footer.append(&status_bar_lbl);

    files_page.append(&cap_header);
    files_page.append(&cap_edit_row);
    files_page.append(&cap_bar);
    files_page.append(&file_search);
    files_page.append(&files_scroll);
    files_page.append(&files_footer);

    inner_stack.add_named(&files_page, Some("files"));

    // --- REFRESH FILES UI CLOSURE ---
    let refresh_files_ui: Rc<dyn Fn()> = {
        let sess_r = session_rc.clone();
        let list_r = files_list.clone();
        let cap_l = cap_lbl.clone();
        let cap_b = cap_bar.clone();
        let q_r = file_query.clone();
        let status_r = status_bar_lbl.clone();
        let tx_r = tx.clone();
        let dlg_r = active_dialog.clone();
        let vault_lbl_r = active_vault_lbl.clone();

        let self_slot: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
        let self_inner = self_slot.clone();

        let closure: Rc<dyn Fn()> = Rc::new(move || {
            while let Some(c) = list_r.first_child() {
                list_r.remove(&c);
            }

            let snapshot = {
                let b = sess_r.borrow();
                b.as_ref().map(|s| {
                    (
                        s.vault_dir.clone(),
                        s.dek,
                        s.index.clone(),
                        vault::calculate_vault_physical_bytes(&s.vault_dir),
                    )
                })
            };

            let Some((v_dir, dek, index, phys_bytes)) = snapshot else {
                return;
            };

            vault_lbl_r.set_label(&v_dir.to_string_lossy());
            let max_bytes = index.max_size_gb.saturating_mul(1024 * 1024 * 1024);
            let dead_bytes: u64 = index.dead_bytes_per_block.values().sum();
            let pct = if max_bytes > 0 {
                (phys_bytes as f64 / max_bytes as f64).clamp(0.0, 1.0)
            } else {
                0.0
            };
            cap_b.set_fraction(pct);
            cap_l.set_label(&if dead_bytes > 0 {
                format!(
                    "{} / {} GB  •  {} dead space",
                    vault::format_bytes(phys_bytes),
                    index.max_size_gb,
                    vault::format_bytes(dead_bytes)
                )
            } else {
                format!("{} / {} GB", vault::format_bytes(phys_bytes), index.max_size_gb)
            });

            let q = q_r.borrow().clone();
            let mut shown = 0;

            for (idx, entry) in index.files.iter().enumerate() {
                if !q.is_empty() && !entry.name.to_lowercase().contains(&q) {
                    continue;
                }

                let row_box = Box::builder().orientation(Orientation::Horizontal).build();
                let btn = Button::builder()
                    .css_classes(vec!["vault-row-btn".to_string()])
                    .hexpand(true)
                    .tooltip_text("Left-click: Preview in RAM  •  Right-click: Export / Replace / Delete")
                    .build();

                let row_inner = Box::builder().orientation(Orientation::Horizontal).spacing(8).build();
                let name_lbl = Label::builder()
                    .label(&entry.name)
                    .halign(Align::Start)
                    .hexpand(true)
                    .ellipsize(gtk4::pango::EllipsizeMode::End)
                    .build();
                let sz_lbl = Label::builder()
                    .label(&vault::format_bytes(entry.original_size))
                    .css_classes(vec!["vault-muted".to_string()])
                    .halign(Align::End)
                    .build();
                row_inner.append(&name_lbl);
                row_inner.append(&sz_lbl);
                btn.set_child(Some(&row_inner));

                // Left-click -> Preview in RAM
                {
                    let vd = v_dir.clone();
                    let ent = entry.clone();
                    let t = tx_r.clone();
                    let st = status_r.clone();
                    btn.connect_clicked(move |_| {
                        st.set_label(&format!("Decrypting {} to RAM...", ent.name));
                        let dest = PathBuf::from(RAM_EXTRACT_DIR).join(&ent.name);
                        let vd2 = vd.clone();
                        let ent2 = ent.clone();
                        let t2 = t.clone();
                        std::thread::spawn(move || {
                            let res = vault::stream_decrypt_file_from_blocks(
                                &vd2, &dek, &ent2, &dest, &t2,
                            )
                            .map(|_| (dest, true));
                            let _ = t2.send(WorkerEvent::ExtractDone(res));
                        });
                    });
                }

                // Right-click menu
                let rc = GestureClick::builder().button(3).build();
                let row_w = row_box.downgrade();
                let vd_m = v_dir.clone();
                let ent_m = entry.clone();
                let tx_m = tx_r.clone();
                let st_m = status_r.clone();
                let dlg_m = dlg_r.clone();
                let sess_m = sess_r.clone();
                let rr_slot = self_inner.clone();

                rc.connect_pressed(move |_, _, _, _| {
                    let Some(parent) = row_w.upgrade() else { return; };
                    let pop = Popover::builder()
                        .css_classes(vec!["vault-popover".to_string()])
                        .autohide(true)
                        .build();
                    pop.set_parent(&parent);
                    pop.connect_closed(|p| {
                        let pw = p.downgrade();
                        glib::idle_add_local_once(move || {
                            if let Some(p) = pw.upgrade() { p.unparent(); }
                        });
                    });

                    let menu = Box::builder().orientation(Orientation::Vertical).spacing(4).build();
                    let b_open = Button::builder()
                        .label("Preview in RAM")
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_export = Button::builder()
                        .label("Export to Disk...")
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_replace = Button::builder()
                        .label("Replace File...")
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_del = Button::builder()
                        .label("Delete from Vault")
                        .css_classes(vec!["vault-danger-btn".to_string()])
                        .build();

                    menu.append(&b_open);
                    menu.append(&b_export);
                    menu.append(&b_replace);
                    menu.append(&b_del);
                    pop.set_child(Some(&menu));

                    // Preview
                    {
                        let vd = vd_m.clone();
                        let ent = ent_m.clone();
                        let t = tx_m.clone();
                        let st = st_m.clone();
                        let pw = pop.downgrade();
                        b_open.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            st.set_label(&format!("Decrypting {} to RAM...", ent.name));
                            let dest = PathBuf::from(RAM_EXTRACT_DIR).join(&ent.name);
                            let vd2 = vd.clone();
                            let ent2 = ent.clone();
                            let t2 = t.clone();
                            std::thread::spawn(move || {
                                let res = vault::stream_decrypt_file_from_blocks(
                                    &vd2, &dek, &ent2, &dest, &t2,
                                )
                                .map(|_| (dest, true));
                                let _ = t2.send(WorkerEvent::ExtractDone(res));
                            });
                        });
                    }

                    // Export
                    {
                        let vd = vd_m.clone();
                        let ent = ent_m.clone();
                        let t = tx_m.clone();
                        let st = st_m.clone();
                        let ds = dlg_m.clone();
                        let pw = pop.downgrade();
                        b_export.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            let dialog = FileChooserNative::builder()
                                .title(&format!("Export {}", ent.name))
                                .action(FileChooserAction::Save)
                                .build();
                            dialog.set_current_name(&ent.name);
                            let vd2 = vd.clone();
                            let ent2 = ent.clone();
                            let t2 = t.clone();
                            let st2 = st.clone();
                            let dc = ds.clone();
                            dialog.connect_response(move |d, res| {
                                if res == ResponseType::Accept {
                                    if let Some(dest) = d.file().and_then(|f| f.path()) {
                                        st2.set_label(&format!("Exporting {}...", ent2.name));
                                        let vd3 = vd2.clone();
                                        let ent3 = ent2.clone();
                                        let t3 = t2.clone();
                                        std::thread::spawn(move || {
                                            let r = vault::stream_decrypt_file_from_blocks(
                                                &vd3, &dek, &ent3, &dest, &t3,
                                            )
                                            .map(|_| (dest, false));
                                            let _ = t3.send(WorkerEvent::ExtractDone(r));
                                        });
                                    }
                                }
                                *dc.borrow_mut() = None;
                            });
                            dialog.show();
                            *ds.borrow_mut() = Some(dialog);
                        });
                    }

                    // Replace
                    {
                        let sm = sess_m.clone();
                        let t = tx_m.clone();
                        let st = st_m.clone();
                        let ds = dlg_m.clone();
                        let pw = pop.downgrade();
                        b_replace.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            let dialog = FileChooserNative::builder()
                                .title("Select Replacement File")
                                .action(FileChooserAction::Open)
                                .build();
                            let sm2 = sm.clone();
                            let t2 = t.clone();
                            let st2 = st.clone();
                            let dc = ds.clone();
                            dialog.connect_response(move |d, res| {
                                if res == ResponseType::Accept {
                                    if let Some(src_path) = d.file().and_then(|f| f.path()) {
                                        let info = {
                                            let b = sm2.borrow();
                                            b.as_ref().map(|s| {
                                                (s.vault_dir.clone(), s.dek, s.index.next_block_id)
                                            })
                                        };
                                        if let Some((vd, dk, mut next_blk)) = info {
                                            let fname = src_path
                                                .file_name()
                                                .map(|n| n.to_string_lossy().to_string())
                                                .unwrap_or_else(|| "file.bin".to_string());
                                            st2.set_label(&format!("Replacing with {}...", fname));
                                            let t3 = t2.clone();
                                            std::thread::spawn(move || {
                                                let r = vault::stream_encrypt_file_to_blocks(
                                                    &vd, &dk, &mut next_blk, &src_path, fname, &t3,
                                                )
                                                .map(|e| (idx, e));
                                                let _ = t3.send(WorkerEvent::ReplaceDone(r));
                                            });
                                        }
                                    }
                                }
                                *dc.borrow_mut() = None;
                            });
                            dialog.show();
                            *ds.borrow_mut() = Some(dialog);
                        });
                    }

                    // Delete
                    {
                        let sm = sess_m.clone();
                        let st = st_m.clone();
                        let rr = rr_slot.clone();
                        let pw = pop.downgrade();
                        b_del.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            let removed_name = {
                                let mut b = sm.borrow_mut();
                                if let Some(s) = b.as_mut() {
                                    if idx < s.index.files.len() {
                                        let old = s.index.files.remove(idx);
                                        for seg in old.segments {
                                            *s.index
                                                .dead_bytes_per_block
                                                .entry(seg.block_id)
                                                .or_insert(0) += seg.cipher_len;
                                        }
                                        let _ = vault::save_vault_index(s);
                                        Some(old.name)
                                    } else {
                                        None
                                    }
                                } else {
                                    None
                                }
                            };
                            if let Some(name) = removed_name {
                                st.set_label(&format!("Deleted {} (run Vacuum to reclaim space).", name));
                                if let Some(cb) = rr.borrow().as_ref() { cb(); }
                            }
                        });
                    }

                    pop.popup();
                });
                btn.add_controller(rc);

                row_box.append(&btn);
                list_r.append(&row_box);
                shown += 1;
            }

            if shown == 0 {
                list_r.append(
                    &Label::builder()
                        .label(if q.is_empty() {
                            "Vault is empty. Click '+ Add File' below to encrypt files!"
                        } else {
                            "No matching files."
                        })
                        .justify(gtk4::Justification::Center)
                        .css_classes(vec!["vault-muted".to_string()])
                        .margin_top(28)
                        .build(),
                );
            }
        });

        *self_slot.borrow_mut() = Some(closure.clone());
        closure
    };

    // --- PASSWORDS TAB ---
    let passwords_view =
        passwords::build_passwords_view(session_rc.clone(), refresh_files_ui.clone());
    inner_stack.add_named(&passwords_view.root, Some("passwords"));

    main_stack.add_named(&vault_root, Some("vault"));

    // Tab switching inside unlocked vault
    {
        let istk = inner_stack.clone();
        let bf = tab_files_btn.clone();
        let bp = tab_pass_btn.clone();
        let rf = refresh_files_ui.clone();
        tab_files_btn.connect_clicked(move |_| {
            istk.set_visible_child_name("files");
            bf.add_css_class("active");
            bp.remove_css_class("active");
            rf();
        });
    }
    {
        let istk = inner_stack.clone();
        let bf = tab_files_btn.clone();
        let bp = tab_pass_btn.clone();
        let rp = passwords_view.reload.clone();
        tab_pass_btn.connect_clicked(move |_| {
            istk.set_visible_child_name("passwords");
            bp.add_css_class("active");
            bf.remove_css_class("active");
            rp();
        });
    }

    // =========================================================================
    // HELPERS: REFRESH UNLOCK SCREEN & LOCK VAULT
    // =========================================================================
    let refresh_unlock_screen: Rc<dyn Fn()> = {
        let v_ent = vault_dir_entry.clone();
        let v_stat = vault_status_lbl.clone();
        let use_f = use_file_mode.clone();
        let usb_b = usb_mode_btn.clone();
        let file_b = file_mode_btn.clone();
        let usb_p = usb_panel.clone();
        let file_p = file_panel.clone();
        let usb_lbl = usb_status_lbl.clone();
        let pin_ent = unlock_pin_entry.clone();
        let rec_box = recent_box.clone();
        let cfg_r = cfg_rc.clone();

        let self_slot: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
        let self_inner = self_slot.clone();

        let f: Rc<dyn Fn()> = Rc::new(move || {
            // Update key source mode visuals
            let is_file = use_f.get();
            if is_file {
                file_b.add_css_class("active");
                usb_b.remove_css_class("active");
                usb_p.set_visible(false);
                file_p.set_visible(true);
            } else {
                usb_b.add_css_class("active");
                file_b.remove_css_class("active");
                usb_p.set_visible(true);
                file_p.set_visible(false);

                if let Some(kp) = vault::find_usb_keyfile() {
                    usb_lbl.set_label(&format!("󰄬 USB Key Ready: {}", kp.display()));
                    usb_lbl.remove_css_class("vault-muted");
                    usb_lbl.add_css_class("vault-ok");
                } else {
                    usb_lbl.set_label(&format!("Insert USB with {}...", KEYFILE_NAME));
                    usb_lbl.remove_css_class("vault-ok");
                    usb_lbl.add_css_class("vault-muted");
                }
            }

            // Check vault folder status + whether PIN is required
            let dir_str = v_ent.text().trim().to_string();
            if dir_str.is_empty() {
                v_stat.set_label("Choose an existing vault folder or click '+ Create New Vault'.");
                pin_ent.set_visible(true);
            } else {
                let p = Path::new(&dir_str);
                match vault::read_vault_header(p) {
                    Ok(hdr) => {
                        if hdr.requires_pin {
                            v_stat.set_label("󰄬 Valid .lilar vault found (PIN required).");
                            pin_ent.set_visible(true);
                        } else {
                            v_stat.set_label("󰄬 Valid .lilar vault found (Keyfile only, no PIN).");
                            pin_ent.set_visible(false);
                        }
                    }
                    Err(_) => {
                        v_stat.set_label(&format!("No {} found in this folder.", INDEX_FILENAME));
                        pin_ent.set_visible(true);
                    }
                }
            }

            // Rebuild recent vault chips
            while let Some(c) = rec_box.first_child() {
                rec_box.remove(&c);
            }
            let recents = cfg_r.borrow().recent_vaults.clone();
            if !recents.is_empty() {
                rec_box.set_visible(true);
                for r in recents.into_iter().take(3) {
                    let short = Path::new(&r)
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| r.clone());
                    let chip = Button::builder()
                        .label(&short)
                        .css_classes(vec!["vault-chip".to_string()])
                        .tooltip_text(&r)
                        .build();
                    let ve = v_ent.clone();
                    let rr = self_inner.clone();
                    chip.connect_clicked(move |_| {
                        ve.set_text(&r);
                        if let Some(cb) = rr.borrow().as_ref() { cb(); }
                    });
                    rec_box.append(&chip);
                }
            } else {
                rec_box.set_visible(false);
            }
        });

        *self_slot.borrow_mut() = Some(f.clone());
        f
    };

    let lock_vault_action: Rc<dyn Fn()> = {
        let sess_l = session_rc.clone();
        let wipe_pw = passwords_view.wipe.clone();
        let mstk = main_stack.clone();
        let pin_l = unlock_pin_entry.clone();
        let err_l = unlock_err_lbl.clone();
        let ref_u = refresh_unlock_screen.clone();
        Rc::new(move || {
            *sess_l.borrow_mut() = None; // Drop zeroizes DEK via write_volatile + fence
            wipe_pw();
            let _ = fs::remove_dir_all(RAM_EXTRACT_DIR);
            pin_l.set_text("");
            err_l.set_visible(false);
            mstk.set_visible_child_name("unlock");
            ref_u();
        })
    };

    // Wipe RAM & /dev/shm on window close
    {
        let lock_close = lock_vault_action.clone();
        window.connect_close_request(move |_| {
            lock_close();
            glib::Propagation::Proceed
        });
    }

    // USB hotplug monitor (auto-detect on insert, auto-lock on remove if unlocked via USB)
    let vol_monitor = gio::VolumeMonitor::get();
    {
        let ref_u = refresh_unlock_screen.clone();
        let sess_chk = session_rc.clone();
        vol_monitor.connect_mount_added(move |_, _| {
            if sess_chk.borrow().is_none() {
                ref_u();
            }
        });
    }
    {
        let lock_cb = lock_vault_action.clone();
        let ref_u = refresh_unlock_screen.clone();
        let sess_chk = session_rc.clone();
        vol_monitor.connect_mount_removed(move |_, _| {
            let unlocked_usb = sess_chk
                .borrow()
                .as_ref()
                .map(|s| s.unlocked_via_usb)
                .unwrap_or(false);
            if unlocked_usb && vault::find_usb_keyfile().is_none() {
                lock_cb();
            } else if sess_chk.borrow().is_none() {
                ref_u();
            }
        });
    }
    window.connect_destroy(move |_| {
        let _keep = &vol_monitor;
    });

    // =========================================================================
    // WIRE UNLOCK & CREATE HANDLERS
    // =========================================================================
    {
        let ref_u = refresh_unlock_screen.clone();
        vault_dir_entry.connect_changed(move |_| ref_u());
    }
    {
        let dlg_s = active_dialog.clone();
        let ve = vault_dir_entry.clone();
        let ref_u = refresh_unlock_screen.clone();
        browse_vault_btn.connect_clicked(move |_| {
            let d = FileChooserNative::builder()
                .title("Select Vault Folder")
                .action(FileChooserAction::SelectFolder)
                .build();
            let ve2 = ve.clone();
            let ru = ref_u.clone();
            let dc = dlg_s.clone();
            d.connect_response(move |dlg, res| {
                if res == ResponseType::Accept {
                    if let Some(p) = dlg.file().and_then(|f| f.path()) {
                        ve2.set_text(&p.to_string_lossy());
                        ru();
                    }
                }
                *dc.borrow_mut() = None;
            });
            d.show();
            *dlg_s.borrow_mut() = Some(d);
        });
    }
    {
        let uf = use_file_mode.clone();
        let cfg_m = cfg_rc.clone();
        let ru = refresh_unlock_screen.clone();
        usb_mode_btn.connect_clicked(move |_| {
            uf.set(false);
            cfg_m.borrow_mut().key_mode = "usb".to_string();
            vault::save_app_config(&cfg_m.borrow());
            ru();
        });
    }
    {
        let uf = use_file_mode.clone();
        let cfg_m = cfg_rc.clone();
        let ru = refresh_unlock_screen.clone();
        file_mode_btn.connect_clicked(move |_| {
            uf.set(true);
            cfg_m.borrow_mut().key_mode = "file".to_string();
            vault::save_app_config(&cfg_m.borrow());
            ru();
        });
    }
    {
        let ru = refresh_unlock_screen.clone();
        usb_rescan_btn.connect_clicked(move |_| ru());
    }
    {
        let dlg_s = active_dialog.clone();
        let ke = keyfile_entry.clone();
        let cfg_m = cfg_rc.clone();
        browse_key_btn.connect_clicked(move |_| {
            let d = FileChooserNative::builder()
                .title("Select Master Keyfile")
                .action(FileChooserAction::Open)
                .build();
            let ke2 = ke.clone();
            let cm = cfg_m.clone();
            let dc = dlg_s.clone();
            d.connect_response(move |dlg, res| {
                if res == ResponseType::Accept {
                    if let Some(p) = dlg.file().and_then(|f| f.path()) {
                        let s = p.to_string_lossy().to_string();
                        ke2.set_text(&s);
                        cm.borrow_mut().last_keyfile = s;
                        vault::save_app_config(&cm.borrow());
                    }
                }
                *dc.borrow_mut() = None;
            });
            d.show();
            *dlg_s.borrow_mut() = Some(d);
        });
    }

    // Attempt Unlock
    let do_unlock: Rc<dyn Fn()> = {
        let ve = vault_dir_entry.clone();
        let uf = use_file_mode.clone();
        let ke = keyfile_entry.clone();
        let pe = unlock_pin_entry.clone();
        let err = unlock_err_lbl.clone();
        let sess_u = session_rc.clone();
        let cfg_u = cfg_rc.clone();
        let mstk = main_stack.clone();
        let istk = inner_stack.clone();
        let bf = tab_files_btn.clone();
        let bp = tab_pass_btn.clone();
        let rf = refresh_files_ui.clone();

        Rc::new(move || {
            let v_dir_str = ve.text().trim().to_string();
            if v_dir_str.is_empty() {
                err.set_label("Select a vault folder first.");
                err.set_visible(true);
                return;
            }
            let (key_path, via_usb) = if uf.get() {
                let k_str = ke.text().trim().to_string();
                if k_str.is_empty() {
                    err.set_label("Pick a keyfile on disk first.");
                    err.set_visible(true);
                    return;
                }
                (PathBuf::from(k_str), false)
            } else {
                match vault::find_usb_keyfile() {
                    Some(kp) => (kp, true),
                    None => {
                        err.set_label("No USB keyfile (.lily_master.key) detected!");
                        err.set_visible(true);
                        return;
                    }
                }
            };

            let pin = pe.text().to_string();
            match vault::unlock_vault(Path::new(&v_dir_str), &key_path, &pin, via_usb) {
                Ok(session) => {
                    pe.set_text("");
                    err.set_visible(false);
                    {
                        let mut c = cfg_u.borrow_mut();
                        if !via_usb {
                            c.last_keyfile = key_path.to_string_lossy().to_string();
                        }
                        vault::record_recent_vault(&mut c, &v_dir_str);
                    }
                    *sess_u.borrow_mut() = Some(session);
                    istk.set_visible_child_name("files");
                    bf.add_css_class("active");
                    bp.remove_css_class("active");
                    rf();
                    mstk.set_visible_child_name("vault");
                }
                Err(msg) => {
                    pe.set_text("");
                    err.set_label(&msg);
                    err.set_visible(true);
                }
            }
        })
    };
    {
        let u = do_unlock.clone();
        unlock_btn.connect_clicked(move |_| u());
    }
    {
        let u = do_unlock.clone();
        unlock_pin_entry.connect_activate(move |_| u());
    }

    // Create New Vault screen navigation & handlers
    {
        let mstk = main_stack.clone();
        let cke = c_key_entry.clone();
        let cerr = create_err_lbl.clone();
        goto_create_btn.connect_clicked(move |_| {
            cerr.set_visible(false);
            if cke.text().trim().is_empty() {
                if let Some(usb_dir) = vault::find_first_usb_mount_dir() {
                    cke.set_text(&usb_dir.join(KEYFILE_NAME).to_string_lossy());
                }
            }
            mstk.set_visible_child_name("create");
        });
    }
    {
        let mstk = main_stack.clone();
        let ru = refresh_unlock_screen.clone();
        back_to_unlock_btn.connect_clicked(move |_| {
            mstk.set_visible_child_name("unlock");
            ru();
        });
    }
    {
        let dlg_s = active_dialog.clone();
        let cve = c_vault_entry.clone();
        c_vault_btn.connect_clicked(move |_| {
            let d = FileChooserNative::builder()
                .title("Select Folder for New Vault")
                .action(FileChooserAction::SelectFolder)
                .build();
            let e2 = cve.clone();
            let dc = dlg_s.clone();
            d.connect_response(move |dlg, res| {
                if res == ResponseType::Accept {
                    if let Some(p) = dlg.file().and_then(|f| f.path()) {
                        e2.set_text(&p.to_string_lossy());
                    }
                }
                *dc.borrow_mut() = None;
            });
            d.show();
            *dlg_s.borrow_mut() = Some(d);
        });
    }
    {
        let cke = c_key_entry.clone();
        let cerr = create_err_lbl.clone();
        c_key_usb_btn.connect_clicked(move |_| {
            if let Some(usb_dir) = vault::find_first_usb_mount_dir() {
                cke.set_text(&usb_dir.join(KEYFILE_NAME).to_string_lossy());
                cerr.set_visible(false);
            } else {
                cerr.set_label("No mounted USB drive found. Plug one in or click 'Choose File'.");
                cerr.set_visible(true);
            }
        });
    }
    {
        let dlg_s = active_dialog.clone();
        let cke = c_key_entry.clone();
        c_key_file_btn.connect_clicked(move |_| {
            let d = FileChooserNative::builder()
                .title("Choose Where to Save Master Keyfile")
                .action(FileChooserAction::Save)
                .build();
            d.set_current_name(KEYFILE_NAME);
            let e2 = cke.clone();
            let dc = dlg_s.clone();
            d.connect_response(move |dlg, res| {
                if res == ResponseType::Accept {
                    if let Some(p) = dlg.file().and_then(|f| f.path()) {
                        e2.set_text(&p.to_string_lossy());
                    }
                }
                *dc.borrow_mut() = None;
            });
            d.show();
            *dlg_s.borrow_mut() = Some(d);
        });
    }
    {
        let cve = c_vault_entry.clone();
        let cke = c_key_entry.clone();
        let cpe = c_pin_entry.clone();
        let cse = c_size_entry.clone();
        let cerr = create_err_lbl.clone();
        let sess_c = session_rc.clone();
        let cfg_c = cfg_rc.clone();
        let v_ent = vault_dir_entry.clone();
        let k_ent = keyfile_entry.clone();
        let mstk = main_stack.clone();
        let istk = inner_stack.clone();
        let bf = tab_files_btn.clone();
        let bp = tab_pass_btn.clone();
        let rf = refresh_files_ui.clone();

        create_submit_btn.connect_clicked(move |_| {
            let v_dir = cve.text().trim().to_string();
            let k_path = cke.text().trim().to_string();
            let pin = cpe.text().to_string();
            let max_gb = cse.text().trim().parse::<u64>().unwrap_or(50).max(1);
            if v_dir.is_empty() || k_path.is_empty() {
                cerr.set_label("Choose both a vault folder and a keyfile location.");
                cerr.set_visible(true);
                return;
            }
            let via_usb = vault::find_first_usb_mount_dir()
                .map(|u| Path::new(&k_path).starts_with(&u))
                .unwrap_or(false);

            match vault::create_new_vault(Path::new(&v_dir), Path::new(&k_path), &pin, max_gb, via_usb) {
                Ok(session) => {
                    cpe.set_text("");
                    cerr.set_visible(false);
                    v_ent.set_text(&v_dir);
                    k_ent.set_text(&k_path);
                    {
                        let mut c = cfg_c.borrow_mut();
                        c.last_keyfile = k_path.clone();
                        c.key_mode = if via_usb { "usb" } else { "file" }.to_string();
                        vault::record_recent_vault(&mut c, &v_dir);
                    }
                    *sess_c.borrow_mut() = Some(session);
                    istk.set_visible_child_name("files");
                    bf.add_css_class("active");
                    bp.remove_css_class("active");
                    rf();
                    mstk.set_visible_child_name("vault");
                }
                Err(msg) => {
                    cerr.set_label(&msg);
                    cerr.set_visible(true);
                }
            }
        });
    }

    // =========================================================================
    // UNLOCKED VAULT CONTROLS (LOCK, LIMIT, SEARCH, ADD FILE, VACUUM, POLLER)
    // =========================================================================
    {
        let lb = lock_vault_action.clone();
        lock_btn.connect_clicked(move |_| lb());
    }
    {
        let cer = cap_edit_row.clone();
        let cee = cap_edit_entry.clone();
        let sc = session_rc.clone();
        edit_cap_btn.connect_clicked(move |_| {
            if let Some(ref s) = *sc.borrow() {
                cee.set_text(&s.index.max_size_gb.to_string());
            }
            cer.set_visible(true);
            cee.grab_focus();
        });
    }
    {
        let cer = cap_edit_row.clone();
        cap_cancel_btn.connect_clicked(move |_| cer.set_visible(false));
    }
    {
        let cer = cap_edit_row.clone();
        let cee = cap_edit_entry.clone();
        let sc = session_rc.clone();
        let rf = refresh_files_ui.clone();
        let commit_cap: Rc<dyn Fn()> = Rc::new(move || {
            if let Ok(gb) = cee.text().trim().parse::<u64>() {
                if let Some(ref mut s) = *sc.borrow_mut() {
                    s.index.max_size_gb = gb.max(1);
                    let _ = vault::save_vault_index(s);
                }
                rf();
            }
            cer.set_visible(false);
        });
        let c1 = commit_cap.clone();
        cap_save_btn.connect_clicked(move |_| c1());
        let c2 = commit_cap.clone();
        cap_edit_entry.connect_activate(move |_| c2());
    }
    {
        let fq = file_query.clone();
        let rf = refresh_files_ui.clone();
        file_search.connect_search_changed(move |e| {
            *fq.borrow_mut() = e.text().trim().to_lowercase();
            rf();
        });
    }
    {
        let ds = active_dialog.clone();
        let sa = session_rc.clone();
        let st = status_bar_lbl.clone();
        let tx_a = tx.clone();
        add_file_btn.connect_clicked(move |_| {
            let info = {
                let b = sa.borrow();
                b.as_ref().map(|s| {
                    let phys = vault::calculate_vault_physical_bytes(&s.vault_dir);
                    let max_b = s.index.max_size_gb.saturating_mul(1024 * 1024 * 1024);
                    (s.vault_dir.clone(), s.dek, s.index.next_block_id, max_b, phys)
                })
            };
            let Some((v_dir, dek, mut next_blk, max_bytes, phys_bytes)) = info else { return; };
            if phys_bytes >= max_bytes {
                st.set_label("Vault full — increase limit or delete/vacuum files.");
                return;
            }
            let d = FileChooserNative::builder()
                .title("Select File to Encrypt into Vault")
                .action(FileChooserAction::Open)
                .build();
            let st2 = st.clone();
            let tx2 = tx_a.clone();
            let dc = ds.clone();
            d.connect_response(move |dlg, res| {
                if res == ResponseType::Accept {
                    if let Some(src_path) = dlg.file().and_then(|f| f.path()) {
                        let file_len = src_path.metadata().map(|m| m.len()).unwrap_or(0);
                        let est = file_len + ((file_len / (CHUNK_SIZE as u64)) + 1) * (TAG_SIZE as u64);
                        if phys_bytes + est > max_bytes {
                            st2.set_label("File exceeds vault soft limit — increase Limit first.");
                        } else {
                            let fname = src_path
                                .file_name()
                                .map(|n| n.to_string_lossy().to_string())
                                .unwrap_or_else(|| "file.bin".to_string());
                            let vd = v_dir.clone();
                            let t3 = tx2.clone();
                            std::thread::spawn(move || {
                                let r = vault::stream_encrypt_file_to_blocks(
                                    &vd, &dek, &mut next_blk, &src_path, fname, &t3,
                                );
                                let _ = t3.send(WorkerEvent::AddDone(r));
                            });
                        }
                    }
                }
                *dc.borrow_mut() = None;
            });
            d.show();
            *ds.borrow_mut() = Some(d);
        });
    }
    {
        let sv = session_rc.clone();
        let st = status_bar_lbl.clone();
        let tx_v = tx.clone();
        vacuum_btn.connect_clicked(move |_| {
            let info = {
                let b = sv.borrow();
                b.as_ref().and_then(|s| {
                    let dead: u64 = s.index.dead_bytes_per_block.values().sum();
                    if dead == 0 {
                        None
                    } else {
                        Some((s.vault_dir.clone(), s.index.clone()))
                    }
                })
            };
            let Some((v_dir, idx_clone)) = info else {
                st.set_label("No dead space to vacuum.");
                return;
            };
            st.set_label("Running Atomic Vacuum...");
            let t2 = tx_v.clone();
            std::thread::spawn(move || {
                let res = vault::run_atomic_vacuum(&v_dir, idx_clone, &t2).map(|(new_idx, old_ids)| {
                    for old_id in old_ids {
                        let _ = fs::remove_file(vault::block_path(&v_dir, old_id));
                    }
                    new_idx
                });
                let _ = t2.send(WorkerEvent::VacuumDone(res));
            });
        });
    }

    // Background worker event poller
    {
        let sp = session_rc.clone();
        let st = status_bar_lbl.clone();
        let rf = refresh_files_ui.clone();
        glib::timeout_add_local(Duration::from_millis(80), move || {
            while let Ok(ev) = rx.try_recv() {
                match ev {
                    WorkerEvent::Progress(_, msg) => st.set_label(&msg),
                    WorkerEvent::AddDone(Ok(entry)) => {
                        {
                            let mut b = sp.borrow_mut();
                            if let Some(s) = b.as_mut() {
                                if let Some(last) = entry.segments.last() {
                                    s.index.next_block_id = s.index.next_block_id.max(last.block_id);
                                }
                                s.index.files.push(entry.clone());
                                let _ = vault::save_vault_index(s);
                            }
                        }
                        st.set_label(&format!("Added {} to vault.", entry.name));
                        rf();
                    }
                    WorkerEvent::AddDone(Err(e)) => st.set_label(&format!("Add failed: {}", e)),
                    WorkerEvent::ReplaceDone(Ok((idx, entry))) => {
                        {
                            let mut b = sp.borrow_mut();
                            if let Some(s) = b.as_mut() {
                                if let Some(last) = entry.segments.last() {
                                    s.index.next_block_id = s.index.next_block_id.max(last.block_id);
                                }
                                if idx < s.index.files.len() {
                                    let old = std::mem::replace(&mut s.index.files[idx], entry.clone());
                                    for seg in old.segments {
                                        *s.index
                                            .dead_bytes_per_block
                                            .entry(seg.block_id)
                                            .or_insert(0) += seg.cipher_len;
                                    }
                                    let _ = vault::save_vault_index(s);
                                }
                            }
                        }
                        st.set_label(&format!("Replaced {} in vault.", entry.name));
                        rf();
                    }
                    WorkerEvent::ReplaceDone(Err(e)) => st.set_label(&format!("Replace failed: {}", e)),
                    WorkerEvent::ExtractDone(Ok((path, open_in_app))) => {
                        if open_in_app {
                            st.set_label(&format!(
                                "Opened in RAM: {}",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            ));
                            if let Ok(uri) = glib::filename_to_uri(&path, None) {
                                let _ = gio::AppInfo::launch_default_for_uri(
                                    &uri,
                                    None::<&gio::AppLaunchContext>,
                                );
                            }
                        } else {
                            st.set_label(&format!("Exported to {}", path.display()));
                        }
                    }
                    WorkerEvent::ExtractDone(Err(e)) => st.set_label(&format!("Decrypt failed: {}", e)),
                    WorkerEvent::VacuumDone(Ok(new_idx)) => {
                        {
                            let mut b = sp.borrow_mut();
                            if let Some(s) = b.as_mut() {
                                s.index = new_idx;
                                let _ = vault::save_vault_index(s);
                            }
                        }
                        st.set_label("Atomic Vacuum complete! Dead space reclaimed.");
                        rf();
                    }
                    WorkerEvent::VacuumDone(Err(e)) => st.set_label(&format!("Vacuum failed: {}", e)),
                }
            }
            glib::ControlFlow::Continue
        });
    }

    refresh_unlock_screen();
    window.present();
}
