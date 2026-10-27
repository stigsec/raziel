# RAZIEL

**RAZIEL** is a lightweight Rust desktop application for securely managing passwords and private notes. It uses authenticated encryption to protect vault contents locally, with no cloud account required.

---

## Features

- **Encrypted vault:** Stores passwords and notes in a single encrypted vault file.
- **Strong key derivation:** Uses Argon2id to derive a 256-bit encryption key from the master password.
- **Authenticated encryption:** Uses AES-256-GCM to provide confidentiality and integrity protection.
- **Password management:** Store, edit, reveal, and copy passwords, along with associated usernames, logins, and optional information.
- **Password generator:** Generate random 20-character passwords using letters, numbers, and supported special characters.
- **Private notes:** Create, edit, view, and delete notes.
- **Master password change:** Re-encrypt the vault with a new encryption key and salt when changing the master password.
- **Custom vault location:** Configure the vault file location through the `RAZIEL_VAULT` environment variable.
- **Cross-platform:** Built with Rust and egui, with support for macOS, Linux, and Windows.
- **Local storage:** Vault contents are stored locally rather than sent to a remote service.

---

## Getting Started

### Dependencies

Ensure you have the Rust toolchain installed, including Cargo.

Installation instructions are available at:

https://www.rust-lang.org/tools/install

Cargo automatically downloads and builds the required dependencies from `Cargo.toml`.

---

### Installation

1. Clone or download the Raziel repository.

2. Open a terminal in the project directory containing `Cargo.toml`.

3. Check that the project compiles:

```bash
cargo check
```

4. Run Raziel:

```bash
cargo run
```

For an optimized release build, use:

```bash
cargo run --release
```

---

## Usage

### First Launch

On the first launch, Raziel asks you to create a master password and confirm it.

This password is used to derive the encryption key that protects your vault. Choose a strong password and keep it somewhere safe.

If the configured vault file does not exist, Raziel initializes a new vault at that location.

### Unlocking the Vault

On subsequent launches, enter your existing master password to unlock the vault.

An incorrect password, corrupted vault, or unsupported vault format prevents the vault from being opened.

### Passwords

The Passwords tab allows you to:

- Add password entries with a name, login, password, and optional information.
- Generate random passwords.
- Reveal or hide stored passwords.
- Copy passwords to the system clipboard.
- Edit and delete existing entries.

### Notes

The Notes tab allows you to create, edit, view, and delete notes. Notes are stored inside the same encrypted vault as password entries.

### Settings

The Settings tab allows you to change the master password.

Enter the new password and select **Apply**. Raziel derives a new encryption key, generates a fresh salt, and re-encrypts the vault. Your existing passwords and notes remain in the vault.

There is no password recovery mechanism, so make sure you remember the new master password.

---

## Vault Location

Raziel uses the `RAZIEL_VAULT` environment variable to determine the location of its encrypted vault file.

If the variable is unset or empty, Raziel uses `vault.enc` in the current working directory.

Relative paths are resolved against the current working directory. An absolute path is recommended to avoid ambiguity.

### macOS

Add the following line to your `~/.zshrc` file:

```bash
export RAZIEL_VAULT="$HOME/Documents/raziel/vault.enc"
```

Create the destination directory if necessary:

```bash
mkdir -p "$HOME/Documents/raziel"
```

Reload your shell configuration:

```bash
source ~/.zshrc
```

Verify the setting:

```bash
printf '%s\n' "$RAZIEL_VAULT"
```

Launch Raziel from the configured terminal:

```bash
cargo run --release
```

Applications launched from Finder may not inherit variables defined in `~/.zshrc`. Launching Raziel from the configured terminal ensures it receives the variable.

### Linux

For Bash, add the following line to `~/.bashrc`:

```bash
export RAZIEL_VAULT="$HOME/Documents/raziel/vault.enc"
```

Create the destination directory and reload the configuration:

```bash
mkdir -p "$HOME/Documents/raziel"
source ~/.bashrc
```

Verify the setting and launch Raziel:

```bash
printf '%s\n' "$RAZIEL_VAULT"
cargo run --release
```

If you use another shell, configure the variable in that shell's appropriate startup file or launch environment.

### Windows

Open PowerShell and configure the variable permanently for your Windows user:

```powershell
[Environment]::SetEnvironmentVariable(
    "RAZIEL_VAULT",
    (Join-Path $HOME "Documents\raziel\vault.enc"),
    "User"
)
```

Open a new terminal so it inherits the updated environment.

Verify the setting:

```powershell
$env:RAZIEL_VAULT
```

Run Raziel from the project directory:

```powershell
cargo run --release
```

To set the variable only for the current PowerShell session, use:

```powershell
$env:RAZIEL_VAULT = Join-Path $HOME "Documents\raziel\vault.enc"
```

### Moving an Existing Vault

To change the vault's location:

1. Close Raziel.
2. Move the existing encrypted vault file to the desired location.
3. Update `RAZIEL_VAULT` to point to the moved file.
4. Restart Raziel.

**Important:** If the configured path does not exist, Raziel treats it as a new vault location. Check the path carefully before launching the application to avoid accidentally creating a separate, empty vault.

Keep backups of your encrypted vault in a secure location.

---

## How It Works

1. **Key Derivation:** Argon2id derives a 256-bit key from the master password and a random 16-byte salt. The configured parameters are a 64,000 KiB memory cost, three iterations, and four parallelism lanes.

2. **Encryption:** Vault data is serialized and encrypted using AES-256-GCM. Each encryption operation uses a fresh, randomly generated 12-byte nonce.

3. **Authenticated Header:** The encrypted file contains a magic identifier, the salt, the nonce, and the ciphertext with its authentication tag. The header is authenticated as additional associated data.

4. **Decryption:** When the user supplies the master password, Raziel derives the corresponding key and attempts to authenticate and decrypt the vault.

5. **Password Changes:** Changing the master password generates a new salt and key, then re-encrypts the vault using the new credentials.

6. **Persistence:** Changes to passwords and notes are saved to the encrypted vault file.

---

## Security Notes

- The master password itself is not stored in the vault.
- AES-256-GCM provides encryption and authentication, allowing tampering to be detected.
- Each encryption operation uses a fresh nonce.
- The vault is encrypted at rest and decrypted in application memory while unlocked.
- There is no built-in master password recovery mechanism.
- Passwords copied to the clipboard may remain available to other applications until the clipboard contents are replaced or cleared.
- Keep backups of the vault file. Losing or damaging it may result in permanent loss of its contents.
- Ensure `RAZIEL_VAULT` points to the correct file before launching Raziel.
- Raziel does not provide cloud synchronization or remote recovery.

---

## Project Structure

```text
raziel/
├── Cargo.toml
└── src/
    └── main.rs
```

The encrypted vault file is stored separately from the Rust source files. Its location is controlled by `RAZIEL_VAULT` or the default `vault.enc` path.

---

## TODO
- zeroize secrets
- favorites
- search

---

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE file](LICENSE) for more details.

---

Developed by [stigsec](https://github.com/stigsec)
