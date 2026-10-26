use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

const VAULT_PATH: &str = "vault.enc";

mod crypto {
    use super::*;

    const MAGIC: &[u8] = b"raziel\x00\x01";
    pub const SALT_LEN: usize = 16;
    const NONCE_LEN: usize = 12;
    const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + NONCE_LEN;
    const CHARSET: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*-_=+?";

    pub fn random<const N: usize>() -> [u8; N] {
        let mut buf = [0u8; N];
        getrandom::getrandom(&mut buf).expect("OS random source unavailable");
        buf
    }

    pub fn generate_password(len: usize) -> String {
        let limit = 256 - (256 % CHARSET.len());
        let mut out = String::with_capacity(len);
        while out.len() < len {
            let buf: [u8; 32] = random();
            for b in buf {
                if out.len() == len {
                    break;
                }
                if (b as usize) < limit {
                    out.push(CHARSET[b as usize % CHARSET.len()] as char);
                }
            }
        }
        out
    }

    pub fn derive_key(password: &str, salt: &[u8]) -> Option<[u8; 32]> {
        let params = Params::new(64_000, 3, 4, Some(32)).ok()?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0u8; 32];
        argon
            .hash_password_into(password.as_bytes(), salt, &mut key)
            .ok()?;
        Some(key)
    }

    pub fn encrypt(key: &[u8; 32], salt: &[u8; SALT_LEN], plaintext: &[u8]) -> Option<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random();
        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(salt);
        out.extend_from_slice(&nonce);

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let ct = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &out,
                },
            )
            .ok()?;
        out.extend_from_slice(&ct);
        Some(out)
    }

    pub fn read_salt(data: &[u8]) -> Option<[u8; SALT_LEN]> {
        if data.len() < HEADER_LEN || &data[..MAGIC.len()] != MAGIC {
            return None;
        }
        data[MAGIC.len()..MAGIC.len() + SALT_LEN].try_into().ok()
    }

    pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < HEADER_LEN {
            return None;
        }
        let (header, ct) = data.split_at(HEADER_LEN);
        let nonce = &header[HEADER_LEN - NONCE_LEN..];
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ct,
                    aad: header,
                },
            )
            .ok()
    }
}

#[derive(Serialize, Deserialize, Default)]
struct Vault {
    passwords: Vec<PasswordEntry>,
    notes: Vec<Note>,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct PasswordEntry {
    name: String,
    login: String,
    password: String,
    info: String,
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct Note {
    title: String,
    body: String,
}

#[derive(Default, PartialEq)]
enum Tab {
    #[default]
    Passwords,
    Notes,
}

#[derive(Default)]
struct MyApp {
    input: String,
    confirm: String,
    first_run: bool,
    unlocked: bool,
    shake_start: Option<f64>,

    key: Option<[u8; 32]>,
    salt: [u8; crypto::SALT_LEN],

    vault: Vault,
    tab: Tab,
    new_pw: PasswordEntry,
    new_note: Note,
    editing_pw: Option<usize>,
    editing_note: Option<usize>,
    show_new_pw: bool,
    revealed: Option<usize>,
}

fn main() -> eframe::Result {
    let first_run = !Path::new(VAULT_PATH).exists();
    let height = if first_run { 100.0 } else { 70.0 };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([260.0, height]),
        ..Default::default()
    };
    eframe::run_native(
        "raziel",
        options,
        Box::new(move |_cc| {
            Ok(Box::new(MyApp {
                first_run,
                ..Default::default()
            }))
        }),
    )
}

impl eframe::App for MyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            if self.unlocked {
                self.vault_screen(ui);
            } else {
                self.login_screen(ui);
            }
        });
    }
}

fn pw_field(ui: &mut egui::Ui, text: &mut String, hint: &str, offset: f32) -> egui::Response {
    ui.horizontal(|ui| {
        ui.add_space(30.0 + offset);
        ui.add(
            egui::TextEdit::singleline(text)
                .password(true)
                .hint_text(hint)
                .desired_width(180.0),
        )
    })
    .inner
}

fn entered(ui: &egui::Ui, r: &egui::Response) -> bool {
    r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

impl MyApp {
    fn try_unlock(&mut self) -> bool {
        if self.first_run {
            if self.input.is_empty() || self.input != self.confirm {
                return false;
            }
            let salt = crypto::random();
            let Some(key) = crypto::derive_key(&self.input, &salt) else {
                return false;
            };
            self.salt = salt;
            self.key = Some(key);
            self.vault = Vault::default();
            self.save();
            self.first_run = false;
            return true;
        }

        let Ok(data) = fs::read(VAULT_PATH) else {
            return false;
        };
        let Some(salt) = crypto::read_salt(&data) else {
            return false;
        };
        let Some(key) = crypto::derive_key(&self.input, &salt) else {
            return false;
        };
        let Some(plain) = crypto::decrypt(&key, &data) else {
            return false;
        };
        let Ok(vault) = serde_json::from_slice(&plain) else {
            return false;
        };
        self.salt = salt;
        self.key = Some(key);
        self.vault = vault;
        true
    }

    fn save(&self) {
        let Some(key) = &self.key else { return };
        let Ok(json) = serde_json::to_vec(&self.vault) else {
            return;
        };
        let Some(blob) = crypto::encrypt(key, &self.salt, &json) else {
            eprintln!("encryption failed, vault not saved");
            return;
        };
        let tmp = format!("{VAULT_PATH}.tmp");
        if let Err(e) = fs::write(&tmp, blob).and_then(|_| fs::rename(&tmp, VAULT_PATH)) {
            eprintln!("could not save vault: {e}");
        }
    }

    fn login_screen(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        let mut offset = 0.0_f32;
        if let Some(start) = self.shake_start {
            let elapsed = now - start;
            if elapsed < 0.4 {
                let decay = 1.0 - elapsed / 0.4;
                offset = ((elapsed * 60.0).sin() * 12.0 * decay) as f32;
                ui.ctx().request_repaint();
            } else {
                self.shake_start = None;
            }
        }

        ui.add_space(14.0);
        let hint = if self.first_run {
            "new password"
        } else {
            "password"
        };
        let r1 = pw_field(ui, &mut self.input, hint, offset);
        let e1 = entered(ui, &r1);

        let submit;
        if self.first_run {
            ui.add_space(6.0);
            let r2 = pw_field(ui, &mut self.confirm, "confirm password", offset);
            let e2 = entered(ui, &r2);

            if e1 {
                r2.request_focus();
            } else if !r2.has_focus() {
                r1.request_focus();
            }
            submit = e2;
        } else {
            submit = e1;
            r1.request_focus();
        }

        if submit {
            if self.try_unlock() {
                self.unlocked = true;
                self.input.clear();
                self.confirm.clear();
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(560.0, 600.0)));
            } else {
                self.input.clear();
                self.confirm.clear();
                self.shake_start = Some(now);
            }
        }
    }

    fn vault_screen(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Passwords, "Passwords");
            ui.selectable_value(&mut self.tab, Tab::Notes, "Notes");
        });
        ui.separator();

        match self.tab {
            Tab::Passwords => self.passwords_tab(ui),
            Tab::Notes => self.notes_tab(ui),
        }
    }

    fn passwords_tab(&mut self, ui: &mut egui::Ui) {
        let width = f32::INFINITY;
        ui.add(
            egui::TextEdit::singleline(&mut self.new_pw.name)
                .hint_text("name (e.g. GitHub)")
                .desired_width(width),
        );
        ui.add(
            egui::TextEdit::singleline(&mut self.new_pw.login)
                .hint_text("email or username")
                .desired_width(width),
        );
        ui.horizontal(|ui| {
            let w = (ui.available_width() - 170.0).max(80.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.new_pw.password)
                    .password(!self.show_new_pw)
                    .hint_text("password")
                    .desired_width(w),
            );
            if ui.button("Generate").clicked() {
                self.new_pw.password = crypto::generate_password(20);
                self.show_new_pw = true;
            }
            ui.checkbox(&mut self.show_new_pw, "Show");
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.new_pw.info)
                .hint_text("info (optional)")
                .desired_width(width),
        );

        let ready = !self.new_pw.name.trim().is_empty()
            && !self.new_pw.login.trim().is_empty()
            && !self.new_pw.password.is_empty();
        ui.horizontal(|ui| {
            let label = if self.editing_pw.is_some() {
                "Save"
            } else {
                "Add"
            };
            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                let entry = std::mem::take(&mut self.new_pw);
                match self.editing_pw.take() {
                    Some(i) if i < self.vault.passwords.len() => self.vault.passwords[i] = entry,
                    _ => self.vault.passwords.push(entry),
                }
                self.show_new_pw = false;
                self.save();
            }
            if self.editing_pw.is_some() && ui.button("Cancel").clicked() {
                self.editing_pw = None;
                self.new_pw = PasswordEntry::default();
                self.show_new_pw = false;
            }
        });

        ui.separator();

        let mut delete = None;
        let mut edit = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, e) in self.vault.passwords.iter().enumerate() {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.strong(&e.name);
                    ui.label(format!("Login: {}", e.login));

                    let shown = self.revealed == Some(i);
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        if shown {
                            ui.monospace(&e.password);
                        } else {
                            ui.label("••••••••");
                        }
                        if !e.info.is_empty() {
                            ui.label(&e.info);
                        }
                    });

                    ui.horizontal(|ui| {
                        if ui.button(if shown { "Hide" } else { "Show" }).clicked() {
                            self.revealed = if shown { None } else { Some(i) };
                        }
                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(e.password.clone());
                        }
                        if ui.button("Edit").clicked() {
                            edit = Some(i);
                        }
                        if ui.button("Delete").clicked() {
                            delete = Some(i);
                        }
                    });
                });
            }
        });

        if let Some(i) = edit {
            self.new_pw = self.vault.passwords[i].clone();
            self.editing_pw = Some(i);
            self.show_new_pw = false;
        }
        if let Some(i) = delete {
            self.vault.passwords.remove(i);
            self.revealed = None;
            self.editing_pw = None;
            self.new_pw = PasswordEntry::default();
            self.save();
        }
    }

    fn notes_tab(&mut self, ui: &mut egui::Ui) {
        ui.add(
            egui::TextEdit::singleline(&mut self.new_note.title)
                .hint_text("title")
                .desired_width(f32::INFINITY),
        );
        ui.add(
            egui::TextEdit::multiline(&mut self.new_note.body)
                .hint_text("note")
                .desired_rows(4)
                .desired_width(f32::INFINITY),
        );

        let ready = !self.new_note.title.trim().is_empty();
        ui.horizontal(|ui| {
            let label = if self.editing_note.is_some() {
                "Save"
            } else {
                "Add"
            };
            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                let note = std::mem::take(&mut self.new_note);
                match self.editing_note.take() {
                    Some(i) if i < self.vault.notes.len() => self.vault.notes[i] = note,
                    _ => self.vault.notes.push(note),
                }
                self.save();
            }
            if self.editing_note.is_some() && ui.button("Cancel").clicked() {
                self.editing_note = None;
                self.new_note = Note::default();
            }
        });

        ui.separator();

        let mut delete = None;
        let mut edit = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, n) in self.vault.notes.iter().enumerate() {
                egui::CollapsingHeader::new(&n.title)
                    .id_salt(i)
                    .show(ui, |ui| {
                        ui.label(&n.body);
                        ui.horizontal(|ui| {
                            if ui.button("Edit").clicked() {
                                edit = Some(i);
                            }
                            if ui.button("Delete").clicked() {
                                delete = Some(i);
                            }
                        });
                    });
            }
        });

        if let Some(i) = edit {
            self.new_note = self.vault.notes[i].clone();
            self.editing_note = Some(i);
        }
        if let Some(i) = delete {
            self.vault.notes.remove(i);
            self.editing_note = None;
            self.new_note = Note::default();
            self.save();
        }
    }
}
