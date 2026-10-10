//! Recipient backup files and optional age encryption.

use crate::private_files;
use anyhow::{Context, bail};
use solana_keypair::Keypair;
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
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
    private_files::validate(&file, path)?;
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

/// Streams `bytes` through age into `file` without a plaintext copy on disk.
fn encrypt_into(file: &File, recipient: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let mut child = Command::new("age")
        .arg("--encrypt")
        .arg("--recipient")
        .arg(recipient)
        .stdin(Stdio::piped())
        .stdout(Stdio::from(file.try_clone()?))
        .stderr(Stdio::inherit())
        .spawn()
        .context("starting age; install age to encrypt keys")?;
    let mut input = child.stdin.take().context("age stdin")?;
    let result = input.write_all(bytes);
    drop(input);
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    result?;
    if !status.success() {
        bail!("age could not encrypt the file");
    }
    Ok(())
}

pub(super) fn create(path: &Path, encrypt_to: Option<&str>) -> anyhow::Result<String> {
    let recipient = RecipientSecretKeys::generate(&mut getrandom::SysRng)
        .context("generating recipient secrets")?;
    let material = recipient.export();
    private_files::create(path, |file| {
        match encrypt_to {
            Some(encrypt_to) => encrypt_into(file, encrypt_to, material.as_bytes())?,
            None => file.write_all(material.as_bytes())?,
        }
        Ok(())
    })?;
    Ok(recipient.derive_public_keys().to_meta_address())
}

/// Decrypts the backup at `path` with `identity` and checks it holds the keys behind
/// `meta_address`.
pub(super) fn verify_readback(
    path: &Path,
    identity: &Path,
    meta_address: &str,
) -> anyhow::Result<()> {
    let keys = load(path, Some(identity))?;
    if keys.derive_public_keys().to_meta_address() != meta_address {
        bail!("the decrypted backup holds different keys");
    }
    Ok(())
}

pub(super) fn export_owner(
    path: &Path,
    recipient: &RecipientSecretKeys,
    ephemeral: &[u8; 32],
    token_account: &[u8; 32],
    encrypt_to: Option<&str>,
) -> anyhow::Result<Keypair> {
    let seed = recipient
        .derive_sweep_destination(ephemeral, token_account)
        .map_err(|error| anyhow::anyhow!("deriving sweep owner: {error:?}"))?;
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let bytes = Zeroizing::new(owner.to_bytes());
    let json = Zeroizing::new(serde_json::to_vec(bytes.as_slice())?);
    private_files::create(path, |file| {
        match encrypt_to {
            Some(encrypt_to) => encrypt_into(file, encrypt_to, &json)?,
            None => file.write_all(&json)?,
        }
        Ok(())
    })?;
    Ok(owner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_files::test_directory as directory;
    use std::{fs, os::unix::fs::PermissionsExt};

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
    fn exported_owner_is_a_private_standard_keypair_and_cannot_be_overwritten() {
        use solana_signer::Signer;
        use stealth_keygen::{EphemeralSecret, derive_payment_with_ephemeral};
        let dir = directory();
        let backup = dir.join("private/nested/recipient.key");
        create(&backup, None).expect("backup");
        let recipient = load(&backup, None).expect("restore");
        let sent = derive_payment_with_ephemeral(
            &recipient.derive_public_keys(),
            &EphemeralSecret::from_bytes([3; 32]),
        )
        .expect("payment");
        let path = dir.join("owner.json");
        let owner = export_owner(
            &path,
            &recipient,
            &sent.announcement.ephemeral_public_key,
            &[4; 32],
            None,
        )
        .expect("export");
        let imported = solana_keypair::read_keypair_file(&path).expect("standard keypair");
        assert_eq!(imported.pubkey(), owner.pubkey());
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        for directory in [dir.join("private"), dir.join("private/nested")] {
            assert_eq!(
                fs::metadata(directory)
                    .expect("metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert!(
            export_owner(
                &path,
                &recipient,
                &sent.announcement.ephemeral_public_key,
                &[4; 32],
                None,
            )
            .is_err()
        );
        assert_eq!(
            solana_keypair::read_keypair_file(&path)
                .expect("preserved")
                .pubkey(),
            owner.pubkey()
        );
        let link = dir.join("link.json");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(
            export_owner(
                &link,
                &recipient,
                &sent.announcement.ephemeral_public_key,
                &[4; 32],
                None,
            )
            .is_err()
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// A fresh age identity and its public recipient, or `None` when age is not installed.
    fn age_identity(dir: &Path) -> Option<(std::path::PathBuf, String)> {
        let identity = dir.join("identity.txt");
        let made = Command::new("age-keygen").arg("-o").arg(&identity).output();
        if !made.as_ref().is_ok_and(|o| o.status.success()) {
            return None;
        }
        let output = Command::new("age-keygen")
            .arg("-y")
            .arg(&identity)
            .output()
            .expect("public recipient");
        assert!(output.status.success());
        fs::set_permissions(&identity, fs::Permissions::from_mode(0o600)).expect("permissions");
        Some((
            identity,
            String::from_utf8(output.stdout)
                .expect("public recipient")
                .trim()
                .to_owned(),
        ))
    }

    fn encrypted_backup_round_trip() {
        let dir = directory();
        let Some((identity, public)) = age_identity(&dir) else {
            eprintln!("skipped: age and age-keygen are not on PATH");
            fs::remove_dir_all(dir).expect("cleanup");
            return;
        };
        let path = dir.join("recipient.age");
        let address = create(&path, Some(&public)).expect("encrypted backup");
        assert!(load(&path, None).is_err());
        assert_eq!(
            load(&path, Some(&identity))
                .expect("decrypt")
                .derive_public_keys()
                .to_meta_address(),
            address
        );
        verify_readback(&path, &identity, &address).expect("read back");
        assert!(verify_readback(&path, &identity, "scope:other").is_err());
        let other = dir.join("other");
        fs::create_dir(&other).expect("directory");
        let (wrong, _) = age_identity(&other).expect("second identity");
        assert!(verify_readback(&path, &wrong, &address).is_err());
        let exported = dir.join("owner.age");
        let owner = export_owner(
            &exported,
            &load(&path, Some(&identity)).expect("keys"),
            &[3; 32],
            &[4; 32],
            Some(&public),
        )
        .expect("encrypted export");
        assert!(solana_keypair::read_keypair_file(&exported).is_err());
        let decrypted = Command::new("age")
            .arg("--decrypt")
            .arg("--identity")
            .arg(&identity)
            .arg(&exported)
            .output()
            .expect("age");
        assert!(decrypted.status.success());
        let bytes: Vec<u8> = serde_json::from_slice(&decrypted.stdout).expect("keypair JSON");
        assert_eq!(bytes, owner.to_bytes());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    #[ignore = "requires age and age-keygen on PATH"]
    fn encrypted_backup_round_trips_with_age() {
        assert!(
            Command::new("age").arg("--version").output().is_ok(),
            "age is required"
        );
        encrypted_backup_round_trip();
    }

    // Runs wherever age is installed, so a developer machine covers it without --ignored.
    #[test]
    fn encrypted_backup_round_trips_when_age_is_installed() {
        encrypted_backup_round_trip();
    }
}
