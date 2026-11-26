//! Built-in encrypted Passwords view for Lily Vault.
//!
//! Decrypts `passwords.txt` from the unlocked `.lilar` vault straight into RAM
//! (never writing plaintext to disk or `/dev/shm`), auto-saves additions/deletions
//! back into the encrypted vault, and zeroizes RAM on lock or window close.

use crate::vault::{self, UnlockedSession};
use gtk4::gdk;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{
    Align, Box, Button, Entry, GestureClick, Label, Orientation, PolicyType, Popover,
    ScrolledWindow, SearchEntry,
};
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

#[derive(Clone)]
struct PasswordEntry {
    line_idx: usize,
    service: String,
    username: String,
    password: String,
}

pub struct PasswordsView {
    pub root: Box,
    pub reload: Rc<dyn Fn()>,
    pub wipe: Rc<dyn Fn()>,
}

fn parse_entries(content: &str) -> Vec<PasswordEntry> {
    let mut entries = Vec::new();
    for (line_idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.splitn(3, '|').map(|s| s.trim()).collect();
        if parts.len() == 3 {
            entries.push(PasswordEntry {
                line_idx,
                service: parts[0].to_string(),
                username: parts[1].to_string(),
                password: parts[2].to_string(),
            });
        }
    }
    entries.sort_by(|a, b| a.service.to_lowercase().cmp(&b.service.to_lowercase()));
    entries
}

fn generate_quantum_password(len: usize) -> (String, bool) {
    const CHARSET: &[u8] =
        b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*-_";

    let mut random_bytes = vec![0u8; len * 2];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut f, &mut random_bytes);
    }

    let mut quantum_success = false;
    let url = "https://lizaonair.com/qrng/?min=100000000&max=999999999";
    if let Ok(output) = std::process::Command::new("curl")
        .args(["-sL", "-H", "Accept: application/json", "--max-time", "2", url])
        .output()
    {
        if output.status.success() {
            if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                if let Some(num) = json.get("value").and_then(|v| v.as_u64()) {
                    let q_bytes = num.to_string().into_bytes();
                    if !q_bytes.is_empty() {
                        for (i, byte) in random_bytes.iter_mut().enumerate() {
                            *byte ^= q_bytes[i % q_bytes.len()];
                        }
                        quantum_success = true;
                    }
                }
            }
        }
    }

    let mut password = String::new();
    let max_valid = 256 - (256 % CHARSET.len());
    for byte in &random_bytes {
        let b = *byte as usize;
        if b < max_valid {
            password.push(CHARSET[b % CHARSET.len()] as char);
            if password.len() == len {
                break;
            }
        }
    }
    vault::zeroize_bytes(&mut random_bytes);

    while password.len() < len {
        let mut fb = [0u8; 1];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let _ = std::io::Read::read_exact(&mut f, &mut fb);
            let b = fb[0] as usize;
            if b < max_valid {
                password.push(CHARSET[b % CHARSET.len()] as char);
            }
        } else {
            password.push(CHARSET[password.len() % CHARSET.len()] as char);
        }
    }

    (password, quantum_success)
}

fn copy_to_clipboard(text: &str) {
    if let Some(display) = gdk::Display::default() {
        display.clipboard().set_text(text);
    }
}

pub fn build_passwords_view(
    session_rc: Rc<RefCell<Option<UnlockedSession>>>,
    on_vault_changed: Rc<dyn Fn()>,
) -> PasswordsView {
    let root = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(10)
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(14)
        .margin_end(14)
        .hexpand(true)
        .vexpand(true)
        .build();

    let search_entry = SearchEntry::builder()
        .placeholder_text("Search encrypted vault logins...")
        .css_classes(vec!["vault-entry".to_string()])
        .build();

    let status_lbl = Label::builder()
        .label("")
        .halign(Align::Start)
        .css_classes(vec!["vault-muted".to_string()])
        .visible(false)
        .build();

    let scrolled = ScrolledWindow::builder()
        .hscrollbar_policy(PolicyType::Never)
        .vscrollbar_policy(PolicyType::Automatic)
        .vexpand(true)
        .hexpand(true)
        .build();

    let list_container = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(4)
        .build();
    scrolled.set_child(Some(&list_container));

    // In-RAM plaintext buffer (zeroized on lock/close)
    let ram_content: Rc<RefCell<Option<String>>> = Rc::new(RefCell::new(None));
    let revealed_set: Rc<RefCell<HashSet<usize>>> = Rc::new(RefCell::new(HashSet::new()));
    let current_query = Rc::new(RefCell::new(String::new()));

    // --- Collapsible "+ New Login" Form ---
    let toggle_btn = Button::builder()
        .label("+ New Vault Login")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .build();

    let form_box = Box::builder()
        .orientation(Orientation::Vertical)
        .spacing(6)
        .css_classes(vec!["vault-card".to_string()])
        .visible(false)
        .build();

    let service_entry = Entry::builder()
        .placeholder_text("Service (e.g. GitHub, Email)...")
        .css_classes(vec!["vault-entry".to_string()])
        .build();

    let user_entry = Entry::builder()
        .placeholder_text("Username / Email...")
        .css_classes(vec!["vault-entry".to_string()])
        .build();

    let pass_row = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();

    let pass_entry = Entry::builder()
        .placeholder_text("Password...")
        .css_classes(vec!["vault-entry".to_string()])
        .hexpand(true)
        .build();

    let gen_btn = Button::builder()
        .label("Gen")
        .css_classes(vec!["vault-btn".to_string()])
        .tooltip_text("Generate quantum-modulated 18-char password")
        .build();

    {
        let pe = pass_entry.clone();
        gen_btn.connect_clicked(move |btn| {
            btn.set_sensitive(false);
            btn.set_label("...");
            let (tx, rx) = std::sync::mpsc::channel::<(String, bool)>();
            let b_c = btn.clone();
            let p_c = pe.clone();
            std::thread::spawn(move || {
                let _ = tx.send(generate_quantum_password(18));
            });
            glib::timeout_add_local(Duration::from_millis(40), move || match rx.try_recv() {
                Ok((pwd, is_q)) => {
                    p_c.set_text(&pwd);
                    b_c.set_sensitive(true);
                    b_c.set_label(if is_q { "Quantum!" } else { "Local" });
                    let br = b_c.clone();
                    glib::timeout_add_local_once(Duration::from_millis(1200), move || {
                        br.set_label("Gen");
                    });
                    glib::ControlFlow::Break
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => glib::ControlFlow::Continue,
                Err(_) => {
                    b_c.set_sensitive(true);
                    b_c.set_label("Gen");
                    glib::ControlFlow::Break
                }
            });
        });
    }

    pass_row.append(&pass_entry);
    pass_row.append(&gen_btn);

    let form_actions = Box::builder()
        .orientation(Orientation::Horizontal)
        .spacing(6)
        .build();

    let save_btn = Button::builder()
        .label("Save to Vault")
        .css_classes(vec!["vault-primary-btn".to_string()])
        .hexpand(true)
        .build();

    let cancel_btn = Button::builder()
        .label("Cancel")
        .css_classes(vec!["vault-btn".to_string()])
        .build();

    form_actions.append(&save_btn);
    form_actions.append(&cancel_btn);

    form_box.append(&service_entry);
    form_box.append(&user_entry);
    form_box.append(&pass_row);
    form_box.append(&form_actions);

    {
        let fb = form_box.clone();
        let se = service_entry.clone();
        toggle_btn.connect_clicked(move |b| {
            b.set_visible(false);
            fb.set_visible(true);
            se.grab_focus();
        });
    }
    {
        let fb = form_box.clone();
        let tb = toggle_btn.clone();
        cancel_btn.connect_clicked(move |_| {
            fb.set_visible(false);
            tb.set_visible(true);
        });
    }

    root.append(&search_entry);
    root.append(&status_lbl);
    root.append(&scrolled);
    root.append(&toggle_btn);
    root.append(&form_box);

    // Render list helper
    let render_list: Rc<dyn Fn()> = {
        let list_c = list_container.clone();
        let ram_c = ram_content.clone();
        let query_c = current_query.clone();
        let rev_c = revealed_set.clone();
        let sess_c = session_rc.clone();
        let changed_c = on_vault_changed.clone();
        let status_c = status_lbl.clone();

        let self_slot: Rc<RefCell<Option<Rc<dyn Fn()>>>> = Rc::new(RefCell::new(None));
        let self_inner = self_slot.clone();

        let f: Rc<dyn Fn()> = Rc::new(move || {
            while let Some(child) = list_c.first_child() {
                list_c.remove(&child);
            }

            let Some(raw) = ram_c.borrow().clone() else {
                return;
            };
            let q = query_c.borrow().clone();
            let entries = parse_entries(&raw);
            let mut shown = 0;

            for item in entries {
                if !q.is_empty()
                    && !item.service.to_lowercase().contains(&q)
                    && !item.username.to_lowercase().contains(&q)
                {
                    continue;
                }

                let is_revealed = rev_c.borrow().contains(&item.line_idx);
                let row_box = Box::builder().orientation(Orientation::Horizontal).build();

                let btn = Button::builder()
                    .css_classes(vec!["vault-row-btn".to_string()])
                    .hexpand(true)
                    .tooltip_text("Left-click: copy password  •  Right-click: options")
                    .build();

                let inner = Box::builder()
                    .orientation(Orientation::Vertical)
                    .spacing(2)
                    .build();

                let top = Box::builder()
                    .orientation(Orientation::Horizontal)
                    .spacing(8)
                    .build();

                let srv_lbl = Label::builder()
                    .label(&format!("󰌾 {}", item.service))
                    .halign(Align::Start)
                    .hexpand(true)
                    .ellipsize(gtk4::pango::EllipsizeMode::End)
                    .build();

                let copy_lbl = Label::builder()
                    .label("Copy")
                    .css_classes(vec!["vault-badge".to_string()])
                    .halign(Align::End)
                    .build();

                top.append(&srv_lbl);
                top.append(&copy_lbl);
                inner.append(&top);

                if !item.username.is_empty() {
                    let usr_lbl = Label::builder()
                        .label(&item.username)
                        .halign(Align::Start)
                        .css_classes(vec!["vault-muted".to_string()])
                        .ellipsize(gtk4::pango::EllipsizeMode::End)
                        .build();
                    inner.append(&usr_lbl);
                }

                if is_revealed {
                    let pass_lbl = Label::builder()
                        .label(&format!("Pass: {}", item.password))
                        .halign(Align::Start)
                        .css_classes(vec!["vault-badge".to_string()])
                        .ellipsize(gtk4::pango::EllipsizeMode::End)
                        .build();
                    inner.append(&pass_lbl);
                }

                btn.set_child(Some(&inner));

                let pwd_click = item.password.clone();
                let cp_lbl = copy_lbl.clone();
                btn.connect_clicked(move |_| {
                    copy_to_clipboard(&pwd_click);
                    cp_lbl.set_label("Copied!");
                    let r = cp_lbl.clone();
                    glib::timeout_add_local_once(Duration::from_millis(1200), move || {
                        r.set_label("Copy");
                    });
                });

                // Right-click menu
                let rc = GestureClick::builder().button(3).build();
                let row_w = row_box.downgrade();
                let usr_m = item.username.clone();
                let pwd_m = item.password.clone();
                let cp_m = copy_lbl.clone();
                let idx = item.line_idx;
                let rev_m = rev_c.clone();
                let ram_m = ram_c.clone();
                let sess_m = sess_c.clone();
                let chg_m = changed_c.clone();
                let st_m = status_c.clone();
                let rerender_slot = self_inner.clone();

                rc.connect_pressed(move |_, _, _, _| {
                    let Some(parent) = row_w.upgrade() else {
                        return;
                    };
                    let pop = Popover::builder()
                        .css_classes(vec!["vault-popover".to_string()])
                        .autohide(true)
                        .build();
                    pop.set_parent(&parent);
                    pop.connect_closed(|p| {
                        let pw = p.downgrade();
                        glib::idle_add_local_once(move || {
                            if let Some(p) = pw.upgrade() {
                                p.unparent();
                            }
                        });
                    });

                    let menu = Box::builder()
                        .orientation(Orientation::Vertical)
                        .spacing(4)
                        .build();

                    let b_user = Button::builder()
                        .label("Copy Username")
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_pass = Button::builder()
                        .label("Copy Password")
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_rev = Button::builder()
                        .label(if is_revealed { "Hide Password" } else { "Show Password" })
                        .css_classes(vec!["vault-btn".to_string()])
                        .build();
                    let b_del = Button::builder()
                        .label("Delete Login")
                        .css_classes(vec!["vault-danger-btn".to_string()])
                        .build();

                    menu.append(&b_user);
                    menu.append(&b_pass);
                    menu.append(&b_rev);
                    menu.append(&b_del);
                    pop.set_child(Some(&menu));

                    {
                        let u = usr_m.clone();
                        let pw = pop.downgrade();
                        let cl = cp_m.clone();
                        b_user.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            copy_to_clipboard(&u);
                            cl.set_label("User Copied!");
                            let r = cl.clone();
                            glib::timeout_add_local_once(Duration::from_millis(1200), move || {
                                r.set_label("Copy");
                            });
                        });
                    }
                    {
                        let p_str = pwd_m.clone();
                        let pw = pop.downgrade();
                        let cl = cp_m.clone();
                        b_pass.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            copy_to_clipboard(&p_str);
                            cl.set_label("Copied!");
                            let r = cl.clone();
                            glib::timeout_add_local_once(Duration::from_millis(1200), move || {
                                r.set_label("Copy");
                            });
                        });
                    }
                    {
                        let rv = rev_m.clone();
                        let pw = pop.downgrade();
                        let rr = rerender_slot.clone();
                        b_rev.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            {
                                let mut s = rv.borrow_mut();
                                if s.contains(&idx) { s.remove(&idx); } else { s.insert(idx); }
                            }
                            if let Some(cb) = rr.borrow().as_ref() { cb(); }
                        });
                    }
                    {
                        let rm = ram_m.clone();
                        let sm = sess_m.clone();
                        let cm = chg_m.clone();
                        let stm = st_m.clone();
                        let rv = rev_m.clone();
                        let pw = pop.downgrade();
                        let rr = rerender_slot.clone();
                        b_del.connect_clicked(move |_| {
                            if let Some(p) = pw.upgrade() { p.popdown(); }
                            let next_content = {
                                let borrow = rm.borrow();
                                let Some(cur) = borrow.as_ref() else { return; };
                                let mut lines: Vec<&str> = cur.lines().collect();
                                if idx < lines.len() {
                                    lines.remove(idx);
                                }
                                let mut out = lines.join("\n");
                                if !out.is_empty() { out.push('\n'); }
                                out
                            };
                            let save_res = {
                                let mut sb = sm.borrow_mut();
                                match sb.as_mut() {
                                    Some(sess) => vault::save_passwords_file(sess, &next_content),
                                    None => Err("Vault is locked".to_string()),
                                }
                            };
                            match save_res {
                                Ok(()) => {
                                    *rm.borrow_mut() = Some(next_content);
                                    rv.borrow_mut().remove(&idx);
                                    cm();
                                    if let Some(cb) = rr.borrow().as_ref() { cb(); }
                                }
                                Err(e) => {
                                    stm.set_label(&format!("Save failed: {}", e));
                                    stm.set_visible(true);
                                }
                            }
                        });
                    }

                    pop.popup();
                });
                btn.add_controller(rc);

                row_box.append(&btn);
                list_c.append(&row_box);
                shown += 1;
            }

            if shown == 0 {
                let empty = Label::builder()
                    .label(if q.is_empty() {
                        "No encrypted logins in this vault yet.\nClick '+ New Vault Login' below to add one!"
                    } else {
                        "No matching logins."
                    })
                    .justify(gtk4::Justification::Center)
                    .css_classes(vec!["vault-muted".to_string()])
                    .margin_top(28)
                    .build();
                list_c.append(&empty);
            }
        });

        *self_slot.borrow_mut() = Some(f.clone());
        f
    };

    // Search handler
    {
        let qc = current_query.clone();
        let rl = render_list.clone();
        search_entry.connect_search_changed(move |e| {
            *qc.borrow_mut() = e.text().trim().to_lowercase();
            rl();
        });
    }

    // Save New Login handler
    let commit_save: Rc<dyn Fn()> = {
        let se = service_entry.clone();
        let ue = user_entry.clone();
        let pe = pass_entry.clone();
        let fb = form_box.clone();
        let tb = toggle_btn.clone();
        let rm = ram_content.clone();
        let sm = session_rc.clone();
        let cm = on_vault_changed.clone();
        let rl = render_list.clone();
        let st = status_lbl.clone();

        Rc::new(move || {
            let s = se.text().trim().replace('|', "-");
            let u = ue.text().trim().replace('|', "-");
            let p = pe.text().trim().to_string();
            if s.is_empty() || p.is_empty() {
                return;
            }
            let mut next = rm.borrow().clone().unwrap_or_default();
            if !next.is_empty() && !next.ends_with('\n') {
                next.push('\n');
            }
            next.push_str(&format!("{} | {} | {}\n", s, u, p));

            let res = {
                let mut sb = sm.borrow_mut();
                match sb.as_mut() {
                    Some(sess) => vault::save_passwords_file(sess, &next),
                    None => Err("Vault is locked".to_string()),
                }
            };
            match res {
                Ok(()) => {
                    *rm.borrow_mut() = Some(next);
                    se.set_text("");
                    ue.set_text("");
                    pe.set_text("");
                    fb.set_visible(false);
                    tb.set_visible(true);
                    st.set_visible(false);
                    cm();
                    rl();
                }
                Err(e) => {
                    st.set_label(&format!("Save failed: {}", e));
                    st.set_visible(true);
                }
            }
        })
    };
    {
        let c = commit_save.clone();
        save_btn.connect_clicked(move |_| c());
    }
    {
        let c = commit_save.clone();
        pass_entry.connect_activate(move |_| c());
    }

    let reload: Rc<dyn Fn()> = {
        let sm = session_rc.clone();
        let rm = ram_content.clone();
        let st = status_lbl.clone();
        let rl = render_list.clone();
        let cm = on_vault_changed.clone();
        Rc::new(move || {
            let res = {
                let mut sb = sm.borrow_mut();
                match sb.as_mut() {
                    Some(sess) => vault::load_or_create_passwords_file(sess),
                    None => Err("Vault is locked".to_string()),
                }
            };
            match res {
                Ok(content) => {
                    *rm.borrow_mut() = Some(content);
                    st.set_visible(false);
                    cm();
                    rl();
                }
                Err(e) => {
                    st.set_label(&format!("Failed to load vault passwords: {}", e));
                    st.set_visible(true);
                }
            }
        })
    };

    let wipe: Rc<dyn Fn()> = {
        let rm = ram_content.clone();
        let rv = revealed_set.clone();
        let lc = list_container.clone();
        Rc::new(move || {
            if let Some(mut s) = rm.borrow_mut().take() {
                unsafe {
                    vault::zeroize_bytes(s.as_bytes_mut());
                }
            }
            rv.borrow_mut().clear();
            while let Some(child) = lc.first_child() {
                lc.remove(&child);
            }
        })
    };

    PasswordsView { root, reload, wipe }
}
