# lily-vault

A standalone GTK4 desktop app for creating and unlocking `.lilar` encrypted file & password vaults — 100% compatible with [lily-dashboard](https://github.com/Lilypersilly/lily-dashboard)'s Locker vaults.

## Features

- **Flexible Vault & Key Selection**: Point to any vault folder (with recent-vault shortcuts) and unlock using either an auto-detected **USB `.lily_master.key`** (hotplug-monitored via `gio::VolumeMonitor`) or **any keyfile on disk**.
- **Strong Cryptography**: Argon2id KDF (64 MiB, 3 iterations) + HKDF-SHA256 per-file subkeys + streaming AES-256-GCM (`1 MB` chunks) stored in `block_XXX.lilar` files (up to 10 GB each) with rolling `vault.lilar.bak1..bak5` backups.
- **Built-in Encrypted Passwords**: View, search, copy, generate (quantum-modulated), add, and delete logins stored in the vault's `passwords.txt` strictly in RAM.
- **RAM-Only Previews & Hardened Zeroization**: File previews extract to `/dev/shm/lily-vault` (`0600`) and are wiped on lock/close; the 32-byte master DEK, derived KEKs/subkeys, and in-RAM passwords are zeroized using `write_volatile` + `compiler_fence(Ordering::SeqCst)`.
- **Atomic Vacuum**: Reclaim dead space left behind by replaced or deleted files into fresh `.lilar` blocks.

## Building & Running

```bash
cargo build --release
./target/release/lily-vault
```
