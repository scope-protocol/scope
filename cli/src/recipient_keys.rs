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

pub(super) fn create(path: &Path, encrypt_to: Option<&str>) -> anyhow::Result<String> {
    let recipient = RecipientSecretKeys::generate(&mut getrandom::SysRng)
        .context("generating recipient secrets")?;
    let material = recipient.export();
    private_files::create(path, |file| {
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
        Ok(())
    })?;
    Ok(recipient.derive_public_keys().to_meta_address())
}

pub(super) fn export_owner(
    path: &Path,
    recipient: &RecipientSecretKeys,
    ephemeral: &[u8; 32],
    token_account: &[u8; 32],
) -> anyhow::Result<Keypair> {
    let seed = recipient
        .derive_sweep_destination(ephemeral, token_account)
        .map_err(|error| anyhow::anyhow!("deriving sweep owner: {error:?}"))?;
    let owner = Keypair::new_from_array(*seed.as_bytes());
    let bytes = Zeroizing::new(owner.to_bytes());
    let json = Zeroizing::new(serde_json::to_vec(bytes.as_slice())?);
    private_files::create(path, |file| Ok(file.write_all(&json)?))?;
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
            )
            .is_err()
        );
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
