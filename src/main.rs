use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use eframe::egui;
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const DEFAULT_VAULT_PATH: &str = "vault.enc";

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

    pub fn encrypt(
        key: &[u8; 32],
        salt: &[u8; SALT_LEN],
        plaintext: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce: [u8; NONCE_LEN] = random();
        let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + 16);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(salt);
        out.extend_from_slice(&nonce);

        let cipher = Aes256Gcm::new_from_slice(key).ok()?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &out,
                },
            )
            .ok()?;

        out.extend_from_slice(&ciphertext);
        Some(out)
    }

    pub fn read_salt(data: &[u8]) -> Option<[u8; SALT_LEN]> {
        if data.len() < HEADER_LEN || &data[..MAGIC.len()] != MAGIC {
            return None;
        }

        data[MAGIC.len()..MAGIC.len() + SALT_LEN]
            .try_into()
            .ok()
    }

    pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < HEADER_LEN {
            return None;
        }

        let (header, ciphertext) = data.split_at(HEADER_LEN);
        let nonce = &header[HEADER_LEN - NONCE_LEN..];
        let cipher = Aes256Gcm::new_from_slice(key).ok()?;

        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
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
    Settings,
}

#[derive(Clone, Copy)]
enum PendingDelete {
    Password(usize),
    Note(usize),
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
    vault_path: PathBuf,

    new_master_password: String,
    show_new_master_password: bool,

    status: Option<String>,
    status_error: bool,

    vault: Vault,
    tab: Tab,
    new_pw: PasswordEntry,
    new_note: Note,
    editing_pw: Option<usize>,
    editing_note: Option<usize>,
    show_new_pw: bool,
    revealed: Option<usize>,
    pending_delete: Option<PendingDelete>,
}

fn load_vault_path() -> PathBuf {
    let path = env::var_os("RAZIEL_VAULT")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_VAULT_PATH));

    if path.is_absolute() {
        path
    } else {
        match env::current_dir() {
            Ok(current_dir) => current_dir.join(path),
            Err(_) => path,
        }
    }
}

fn path_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn atomic_write(path: &Path, contents: &[u8]) -> Result<(), String> {
    if path.is_dir() {
        return Err(format!("The vault path is a directory: {}", path.display()));
    }

    let temp_path = path_with_suffix(path, ".tmp");

    if let Err(error) = fs::write(&temp_path, contents) {
        let _ = fs::remove_file(&temp_path);
        return Err(format!(
            "Could not write temporary file {}: {error}",
            temp_path.display()
        ));
    }

    match fs::rename(&temp_path, path) {
        Ok(()) => Ok(()),
        Err(first_error) if path.exists() => {
            let backup_path = path_with_suffix(path, &format!(".bak-{}", std::process::id()));

            if backup_path.exists() {
                let _ = fs::remove_file(&temp_path);
                return Err(format!(
                    "Could not replace {}: {first_error}. A backup already exists at {}",
                    path.display(),
                    backup_path.display()
                ));
            }

            if let Err(backup_error) = fs::rename(path, &backup_path) {
                let _ = fs::remove_file(&temp_path);
                return Err(format!(
                    "Could not replace {}: {first_error}. Could not preserve the original file: {backup_error}",
                    path.display()
                ));
            }

            match fs::rename(&temp_path, path) {
                Ok(()) => {
                    let _ = fs::remove_file(&backup_path);
                    Ok(())
                }
                Err(replace_error) => {
                    let restore_result = fs::rename(&backup_path, path);
                    let _ = fs::remove_file(&temp_path);

                    match restore_result {
                        Ok(()) => Err(format!(
                            "Could not replace {}: {replace_error}. The original file was restored.",
                            path.display()
                        )),
                        Err(restore_error) => Err(format!(
                            "Could not replace {}: {replace_error}. The original file remains at {}: {restore_error}",
                            path.display(),
                            backup_path.display()
                        )),
                    }
                }
            }
        }
        Err(error) => {
            let _ = fs::remove_file(&temp_path);
            Err(format!("Could not write {}: {error}", path.display()))
        }
    }
}

fn save_vault_to(
    path: &Path,
    key: &[u8; 32],
    salt: &[u8; crypto::SALT_LEN],
    vault: &Vault,
) -> Result<(), String> {
    let json = serde_json::to_vec(vault)
        .map_err(|e| format!("Could not serialize the vault: {e}"))?;

    let encrypted = crypto::encrypt(key, salt, &json)
        .ok_or_else(|| "Could not encrypt the vault.".to_owned())?;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Could not create vault directory {}: {e}",
                    parent.display()
                )
            })?;
        }
    }

    atomic_write(path, &encrypted)
}

fn main() -> eframe::Result {
    let vault_path = load_vault_path();
    let first_run = !vault_path.exists();
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
                vault_path,
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

fn pw_field(
    ui: &mut egui::Ui,
    text: &mut String,
    hint: &str,
    offset: f32,
) -> egui::Response {
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

fn entered(ui: &egui::Ui, response: &egui::Response) -> bool {
    response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
}

impl MyApp {
    fn set_status(&mut self, message: impl Into<String>, is_error: bool) {
        self.status = Some(message.into());
        self.status_error = is_error;
    }

    fn clear_status(&mut self) {
        self.status = None;
        self.status_error = false;
    }

    fn show_status(&self, ui: &mut egui::Ui) {
        if let Some(message) = self.status.as_deref() {
            let color = if self.status_error {
                egui::Color32::from_rgb(255, 100, 100)
            } else {
                egui::Color32::from_rgb(100, 200, 120)
            };

            ui.colored_label(color, message);
        }
    }

    fn try_unlock(&mut self) -> Result<(), String> {
        if self.first_run {
            if self.input.is_empty() {
                return Err("The master password cannot be empty.".to_owned());
            }

            if self.input != self.confirm {
                return Err("The passwords do not match.".to_owned());
            }

            let salt: [u8; crypto::SALT_LEN] = crypto::random();
            let key = crypto::derive_key(&self.input, &salt)
                .ok_or_else(|| "Could not derive the encryption key.".to_owned())?;
            let vault = Vault::default();

            save_vault_to(&self.vault_path, &key, &salt, &vault)?;

            self.salt = salt;
            self.key = Some(key);
            self.vault = vault;
            self.first_run = false;

            Ok(())
        } else {
            let data = fs::read(&self.vault_path).map_err(|e| {
                format!(
                    "Could not read vault {}: {e}",
                    self.vault_path.display()
                )
            })?;

            let salt = crypto::read_salt(&data)
                .ok_or_else(|| "Invalid vault file or unsupported vault version.".to_owned())?;
            let key = crypto::derive_key(&self.input, &salt)
                .ok_or_else(|| "Could not derive the encryption key.".to_owned())?;
            let plaintext = crypto::decrypt(&key, &data)
                .ok_or_else(|| "Incorrect password or damaged vault.".to_owned())?;
            let vault: Vault = serde_json::from_slice(&plaintext)
                .map_err(|e| format!("Could not read vault contents: {e}"))?;

            self.salt = salt;
            self.key = Some(key);
            self.vault = vault;

            Ok(())
        }
    }

    fn save(&self) -> Result<(), String> {
        let key = self
            .key
            .as_ref()
            .ok_or_else(|| "The vault is locked.".to_owned())?;

        save_vault_to(&self.vault_path, key, &self.salt, &self.vault)
    }

    fn save_with_status(&mut self) {
        match self.save() {
            Ok(()) => self.clear_status(),
            Err(error) => self.set_status(format!("Could not save vault: {error}"), true),
        }
    }

    fn change_master_password(&mut self) {
        if self.new_master_password.is_empty() {
            self.set_status("The new master password cannot be empty.", true);
            return;
        }

        let new_salt: [u8; crypto::SALT_LEN] = crypto::random();
        let Some(new_key) = crypto::derive_key(&self.new_master_password, &new_salt) else {
            self.set_status("Could not derive the new encryption key.", true);
            return;
        };

        match save_vault_to(&self.vault_path, &new_key, &new_salt, &self.vault) {
            Ok(()) => {
                self.key = Some(new_key);
                self.salt = new_salt;
                self.new_master_password.clear();
                self.show_new_master_password = false;
                self.set_status("Master password changed successfully.", false);
            }
            Err(error) => {
                self.set_status(
                    format!("Could not change the master password: {error}"),
                    true,
                );
            }
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
            match self.try_unlock() {
                Ok(()) => {
                    self.unlocked = true;
                    self.input.clear();
                    self.confirm.clear();
                    self.clear_status();

                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::InnerSize(
                        egui::vec2(560.0, 600.0),
                    ));
                }
                Err(error) => {
                    self.input.clear();
                    self.confirm.clear();
                    self.set_status(error, true);
                    self.shake_start = Some(now);
                }
            }
        }

        self.show_status(ui);
    }

    fn vault_screen(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Passwords, "Passwords");
            ui.selectable_value(&mut self.tab, Tab::Notes, "Notes");
            ui.selectable_value(&mut self.tab, Tab::Settings, "Settings");
        });

        ui.separator();

        match self.tab {
            Tab::Passwords => self.passwords_tab(ui),
            Tab::Notes => self.notes_tab(ui),
            Tab::Settings => self.settings_tab(ui),
        }

        self.confirm_delete(ui);
        self.show_status(ui);
    }

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.label("Change password");

        ui.horizontal(|ui| {
            let width = (ui.available_width() - 70.0).max(80.0);

            ui.add(
                egui::TextEdit::singleline(&mut self.new_master_password)
                    .password(!self.show_new_master_password)
                    .hint_text("new password")
                    .desired_width(width),
            );

            if ui
                .button(if self.show_new_master_password { "Hide" } else { "Show" })
                .clicked()
            {
                self.show_new_master_password = !self.show_new_master_password;
            }
        });

        if ui.button("Apply").clicked() {
            self.change_master_password();
        }
    }

    fn confirm_delete(&mut self, ui: &mut egui::Ui) {
        let Some(target) = self.pending_delete else {
            return;
        };

        let item = match target {
            PendingDelete::Password(index) => {
                self.vault.passwords.get(index).map(|entry| entry.name.clone())
            }
            PendingDelete::Note(index) => {
                self.vault.notes.get(index).map(|note| note.title.clone())
            }
        };

        let Some(item) = item else {
            self.pending_delete = None;
            return;
        };

        let mut decision = None;
        let response = egui::Modal::new(egui::Id::unique("confirm_delete"))
            .show(ui.ctx(), |ui| {
                ui.set_width(180.0);
                ui.spacing_mut().item_spacing.y = 4.0;

                ui.vertical_centered(|ui| {
                    ui.heading("Are you sure?");
                    ui.label(format!("Delete \"{item}\"?"));
                });

                ui.add_space(4.0);

                let button_width = 70.0;
                let gap = ui.spacing().item_spacing.x;
                let pad = ((ui.available_width() - 2.0 * button_width - 3.0 * gap) / 2.0)
                    .max(0.0);

                ui.horizontal(|ui| {
                    ui.add_space(pad);

                    if ui
                        .add(egui::Button::new("Yes").min_size(egui::vec2(button_width, 0.0)))
                        .clicked()
                    {
                        decision = Some(true);
                    }

                    if ui
                        .add(egui::Button::new("No").min_size(egui::vec2(button_width, 0.0)))
                        .clicked()
                    {
                        decision = Some(false);
                    }
                });
            });

        if response.should_close() {
            decision = Some(false);
        }

        match decision {
            Some(true) => {
                match target {
                    PendingDelete::Password(index) => {
                        if index < self.vault.passwords.len() {
                            self.vault.passwords.remove(index);
                        }
                        self.revealed = None;
                        self.editing_pw = None;
                        self.new_pw = PasswordEntry::default();
                    }
                    PendingDelete::Note(index) => {
                        if index < self.vault.notes.len() {
                            self.vault.notes.remove(index);
                        }
                        self.editing_note = None;
                        self.new_note = Note::default();
                    }
                }

                self.pending_delete = None;
                self.save_with_status();
            }
            Some(false) => self.pending_delete = None,
            None => {}
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
            let width = (ui.available_width() - 170.0).max(80.0);

            ui.add(
                egui::TextEdit::singleline(&mut self.new_pw.password)
                    .password(!self.show_new_pw)
                    .hint_text("password")
                    .desired_width(width),
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
            let label = if self.editing_pw.is_some() { "Save" } else { "Add" };

            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                let entry = std::mem::take(&mut self.new_pw);

                match self.editing_pw.take() {
                    Some(index) if index < self.vault.passwords.len() => {
                        self.vault.passwords[index] = entry;
                    }
                    _ => self.vault.passwords.push(entry),
                }

                self.show_new_pw = false;
                self.save_with_status();
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
            for (index, entry) in self.vault.passwords.iter().enumerate() {
                ui.group(|ui| {
                    ui.set_width(ui.available_width());
                    ui.strong(&entry.name);
                    ui.label(format!("Login: {}", entry.login));

                    let shown = self.revealed == Some(index);
                    ui.horizontal(|ui| {
                        ui.label("Password:");
                        if shown {
                            ui.monospace(&entry.password);
                        } else {
                            ui.label("••••••••");
                        }
                    });

                    if !entry.info.is_empty() {
                        ui.label(&entry.info);
                    }

                    ui.horizontal(|ui| {
                        if ui.button(if shown { "Hide" } else { "Show" }).clicked() {
                            self.revealed = if shown { None } else { Some(index) };
                        }

                        if ui.button("Copy").clicked() {
                            ui.ctx().copy_text(entry.password.clone());
                        }

                        if ui.button("Edit").clicked() {
                            edit = Some(index);
                        }

                        if ui.button("Delete").clicked() {
                            delete = Some(index);
                        }
                    });
                });
            }
        });

        if let Some(index) = edit {
            self.new_pw = self.vault.passwords[index].clone();
            self.editing_pw = Some(index);
            self.show_new_pw = false;
        }

        if let Some(index) = delete {
            self.pending_delete = Some(PendingDelete::Password(index));
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
            let label = if self.editing_note.is_some() { "Save" } else { "Add" };

            if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
                let note = std::mem::take(&mut self.new_note);

                match self.editing_note.take() {
                    Some(index) if index < self.vault.notes.len() => {
                        self.vault.notes[index] = note;
                    }
                    _ => self.vault.notes.push(note),
                }

                self.save_with_status();
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
            for (index, note) in self.vault.notes.iter().enumerate() {
                egui::CollapsingHeader::new(&note.title)
                    .id_salt(index)
                    .show(ui, |ui| {
                        ui.label(&note.body);

                        ui.horizontal(|ui| {
                            if ui.button("Edit").clicked() {
                                edit = Some(index);
                            }

                            if ui.button("Delete").clicked() {
                                delete = Some(index);
                            }
                        });
                    });
            }
        });

        if let Some(index) = edit {
            self.new_note = self.vault.notes[index].clone();
            self.editing_note = Some(index);
        }

        if let Some(index) = delete {
            self.pending_delete = Some(PendingDelete::Note(index));
        }
    }
}
