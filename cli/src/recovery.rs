use crate::private_files;
use scope_client::sweep::SweepReport;
use serde::Serialize;
use solana_address::Address;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const HEADER: &[u8] = b"{\"format\":\"scope-recipient-recovery\",\"version\":1}\n";

#[derive(Serialize)]
struct Record<'a> {
    genesis_hash: String,
    ephemeral: String,
    token_account: String,
    destination: String,
    owner: String,
    payment_authority: String,
    attempt_signature: &'a str,
}

pub(super) struct RecoveryJournal {
    file: File,
}

pub(super) fn default_path(backup: &Path) -> PathBuf {
    let mut path = backup.as_os_str().to_owned();
    path.push(".sweeps.jsonl");
    PathBuf::from(path)
}

impl RecoveryJournal {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        private_files::create_parent(path)?;
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        private_files::validate(&file, path)?;
        file.try_lock().map_err(|error| match error {
            std::fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                "recovery journal is already in use",
            ),
            std::fs::TryLockError::Error(error) => error,
        })?;
        let length = file.metadata()?.len();
        let prefix_len = usize::try_from(length.min(HEADER.len() as u64)).expect("header length");
        let mut prefix = [0; HEADER.len()];
        file.read_exact(&mut prefix[..prefix_len])?;
        if prefix[..prefix_len] != HEADER[..prefix_len] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a SCOPE recovery journal",
            ));
        }
        if prefix_len < HEADER.len() {
            file.write_all(&HEADER[prefix_len..])?;
        } else {
            repair_tail(&mut file, length)?;
        }
        file.sync_all()?;
        File::open(private_files::parent(path))?.sync_all()?;
        Ok(Self { file })
    }

    pub(super) fn append(&mut self, report: &SweepReport) -> io::Result<()> {
        let record = Record {
            genesis_hash: Address::new_from_array(report.genesis_hash).to_string(),
            ephemeral: Address::new_from_array(report.ephemeral).to_string(),
            token_account: report.token_account.to_string(),
            destination: report.destination.to_string(),
            owner: report.destination_owner.to_string(),
            payment_authority: report.payment_authority.to_string(),
            attempt_signature: &report.attempt_signature,
        };
        serde_json::to_writer(&mut self.file, &record).map_err(io::Error::other)?;
        self.file.write_all(b"\n")?;
        self.file.sync_data()
    }
}

fn repair_tail(file: &mut File, mut end: u64) -> io::Result<()> {
    let mut bytes = [0; 4096];
    while end > HEADER.len() as u64 {
        let start = end.saturating_sub(bytes.len() as u64);
        let length = (end - start) as usize;
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut bytes[..length])?;
        if let Some(newline) = bytes[..length].iter().rposition(|byte| *byte == b'\n') {
            let complete = start + newline as u64 + 1;
            if complete < file.metadata()?.len() {
                file.set_len(complete)?;
            }
            return Ok(());
        }
        end = start;
    }
    file.set_len(HEADER.len() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt};

    #[test]
    fn checkpoints_are_private_public_only_and_locked() {
        let dir = private_files::test_directory();
        let path = default_path(&dir.join("recipient.age"));
        assert!(path.ends_with("recipient.age.sweeps.jsonl"));
        let mut journal = RecoveryJournal::open(&path).expect("open");
        assert_eq!(
            RecoveryJournal::open(&path).err().expect("locked").kind(),
            io::ErrorKind::WouldBlock
        );
        let report = crate::tests::report();
        journal.append(&report).expect("checkpoint");
        let text = fs::read_to_string(&path).expect("saved");
        let record: serde_json::Value =
            serde_json::from_str(text.lines().nth(1).expect("record")).expect("json");
        assert_eq!(record.as_object().expect("object").len(), 7);
        assert_eq!(
            record["ephemeral"],
            Address::new_from_array(report.ephemeral).to_string()
        );
        assert_eq!(record["token_account"], report.token_account.to_string());
        assert_eq!(record["owner"], report.destination_owner.to_string());
        assert_eq!(
            record["genesis_hash"],
            Address::new_from_array(report.genesis_hash).to_string()
        );
        assert!(record.get("amount").is_none());
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
        drop(journal);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("permissions");
        assert!(RecoveryJournal::open(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).expect("symlink");
        assert!(RecoveryJournal::open(&link).is_err());
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn unrelated_private_files_are_preserved_and_torn_records_are_repaired() {
        let dir = private_files::test_directory();
        let unrelated = dir.join("recipient.key");
        private_files::create(&unrelated, |file| Ok(file.write_all(&[3; 64])?))
            .expect("private file");
        assert!(RecoveryJournal::open(&unrelated).is_err());
        assert_eq!(fs::read(&unrelated).expect("preserved"), [3; 64]);
        let path = dir.join("recovery.jsonl");
        private_files::create(&path, |file| Ok(file.write_all(&HEADER[..12])?))
            .expect("partial header");
        let mut journal = RecoveryJournal::open(&path).expect("complete header");
        let mut report = crate::tests::report();
        journal.append(&report).expect("first record");
        drop(journal);
        let before = fs::read(&path).expect("complete records");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("partial write");
        file.write_all(&vec![b'x'; 5_000]).expect("torn tail");
        drop(file);
        let mut journal = RecoveryJournal::open(&path).expect("repair");
        assert_eq!(fs::read(&path).expect("repaired"), before);
        report.attempt_signature = "next-signature".into();
        journal.append(&report).expect("next record");
        let text = fs::read_to_string(&path).expect("records");
        assert_eq!(text.lines().count(), 3);
        for line in text.lines() {
            serde_json::from_str::<serde_json::Value>(line).expect("valid JSON line");
        }
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }

    #[test]
    fn failed_journal_writes_stop_the_checkpoint_before_stdout() {
        let dir = private_files::test_directory();
        let path = dir.join("recovery.jsonl");
        let mut journal = RecoveryJournal::open(&path).expect("open");
        journal.file = File::open(&path).expect("read-only descriptor");
        let mut output = Vec::new();
        assert!(
            crate::checkpoint(&mut output, Some(&mut journal), &crate::tests::report()).is_err()
        );
        assert!(output.is_empty());
        drop(journal);
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
