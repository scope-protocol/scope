//! Recipient backup files and optional age encryption.

use anyhow::{Context, bail};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
};
use stealth_keygen::RecipientSecretKeys;
use zeroize::Zeroizing;

fn private_file(path: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} must be a regular file with owner-only permissions (chmod 600)",
            path.display()
        );
    }
    Ok(file)
}

pub(super) fn load(path: &Path, identity: Option<&Path>) -> anyhow::Result<RecipientSecretKeys> {
    let file = private_file(path)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(65));
    if let Some(identity) = identity {
        private_file(identity)?;
        let mut child = Command::new("age")
            .arg("--decrypt")
            .arg("--identity")
            .arg(identity)
            .stdin(Stdio::from(file))
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("starting age; install age to load encrypted recipient keys")?;
        let output = child.stdout.take().context("age stdout")?;
        let read = output.take(65).read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > 64 {
            let _ = child.kill();
        }
        let status = child.wait()?;
        read?;
        if !status.success() {
            bail!("age could not decrypt the recipient key file");
        }
    } else {
        file.take(65).read_to_end(&mut bytes)?;
    }
    if bytes.len() != 64 {
        bail!("recipient backup must contain exactly 64 bytes; encrypted files need --identity");
    }
    let mut material = Zeroizing::new([0; 64]);
    material.copy_from_slice(&bytes);
    RecipientSecretKeys::from_bytes(*material).context("invalid recipient private material")
}

pub(super) fn create(path: &Path, encrypt_to: Option<&str>) -> anyhow::Result<String> {
    let recipient = RecipientSecretKeys::generate(&mut getrandom::SysRng)
        .context("generating recipient secrets")?;
    let material = recipient.export();
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| {
            format!(
                "creating {}; existing backups are never overwritten",
                path.display()
            )
        })?;
    let write = (|| -> anyhow::Result<()> {
        if let Some(encrypt_to) = encrypt_to {
            let mut child = Command::new("age")
                .arg("--encrypt")
                .arg("--recipient")
                .arg(encrypt_to)
                .stdin(Stdio::piped())
                .stdout(Stdio::from(file.try_clone()?))
                .stderr(Stdio::inherit())
                .spawn()
                .context("starting age; install age to encrypt recipient keys")?;
            let mut input = child.stdin.take().context("age stdin")?;
            let result = input.write_all(material.as_bytes());
            drop(input);
            if result.is_err() {
                let _ = child.kill();
            }
            let status = child.wait()?;
            result?;
            if !status.success() {
                bail!("age could not encrypt the recipient backup");
            }
        } else {
            file.write_all(material.as_bytes())?;
        }
        file.sync_all()?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    })();
    if let Err(error) = write {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(recipient.derive_public_keys().to_meta_address())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn directory() -> std::path::PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "scope-recipient-keys-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).expect("directory");
        dir
    }

    #[test]
    fn private_backup_round_trips_and_cannot_be_overwritten() {
        let dir = directory();
        let path = dir.join("recipient.key");
        let address = create(&path, None).expect("create");
        let original = load(&path, None).expect("load");
        assert_eq!(original.derive_public_keys().to_meta_address(), address);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        assert!(create(&path, None).is_err());
        assert_eq!(
            load(&path, None).expect("preserved").derive_public_keys(),
            original.derive_public_keys()
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn rejects_public_permissions_symlinks_and_invalid_material() {
        let dir = directory();
        let path = dir.join("recipient.key");
        create(&path, None).expect("create");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
        assert!(load(&path, None).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let link = dir.join("linked.key");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(load(&link, None).is_err());
        for invalid in [vec![0; 64], vec![1; 63], vec![1; 65]] {
            fs::write(&path, invalid).expect("write");
            assert!(load(&path, None).is_err());
        }
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    #[ignore = "requires age and age-keygen on PATH"]
    fn encrypted_backup_round_trips_with_age() {
        let dir = directory();
        let identity = dir.join("identity.txt");
        assert!(
            Command::new("age-keygen")
                .arg("-o")
                .arg(&identity)
                .status()
                .expect("age-keygen")
                .success()
        );
        let output = Command::new("age-keygen")
            .arg("-y")
            .arg(&identity)
            .output()
            .expect("public recipient");
        assert!(output.status.success());
        let public = String::from_utf8(output.stdout).expect("public recipient");
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).expect("permissions");
        let path = dir.join("recipient.age");
        let address = create(&path, Some(public.trim())).expect("encrypted backup");
        assert!(load(&path, None).is_err());
        assert_eq!(
            load(&path, Some(&identity))
                .expect("decrypt")
                .derive_public_keys()
                .to_meta_address(),
            address
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
