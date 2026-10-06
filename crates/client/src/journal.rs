//! Append-only run journal (docs/client.md, Journal): `runs/<run_id>/journal.jsonl`,
//! mode 0600, one writer holding an exclusive lock. Every record is fsynced before
//! the call returns, so an attempt is on disk before its transaction is sent. It
//! holds no secret and no plaintext amount; the amounts live in the input copy.

use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

pub const JOURNAL: &str = "journal.jsonl";
pub const INPUT_COPY: &str = "input.csv";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Record {
    Run {
        run_id: String,
        input_sha256: String,
        mint: String,
        source: String,
        payer: String,
        /// Send order: a random permutation of row indexes, so it does not mirror the file.
        order: Vec<usize>,
    },
    Attempt {
        row: usize,
        signature: String,
        last_valid_block_height: u64,
        /// Source available-balance ciphertext before and after this transfer, hex.
        pre: String,
        post: String,
        /// The signed transaction, hex, resent as is until it lands or expires.
        tx: String,
    },
    Landed {
        row: usize,
        signature: String,
    },
    Done,
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0} is locked by another run")]
    Locked(PathBuf),
    #[error("{path} line {line}: {why}")]
    Corrupt {
        path: PathBuf,
        line: usize,
        why: String,
    },
}

pub struct Journal {
    file: File,
    path: PathBuf,
}

fn io(path: &Path) -> impl Fn(std::io::Error) -> JournalError + '_ {
    move |e| JournalError::Io(path.to_path_buf(), e)
}

fn lock(file: &File, path: &Path) -> Result<(), JournalError> {
    file.try_lock().map_err(|e| match e {
        std::fs::TryLockError::WouldBlock => JournalError::Locked(path.to_path_buf()),
        std::fs::TryLockError::Error(e) => JournalError::Io(path.to_path_buf(), e),
    })
}

/// Writes `bytes` to a new file readable only by the owner; fails if it exists.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io(path))?;
    file.write_all(bytes).map_err(io(path))?;
    file.sync_all().map_err(io(path))
}

/// Takes the exclusive lock on `dir/.lock`, creating both; released when the file drops.
pub fn lock_dir(dir: &Path) -> Result<File, JournalError> {
    std::fs::create_dir_all(dir).map_err(io(dir))?;
    let path = dir.join(".lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(&path)
        .map_err(io(&path))?;
    lock(&file, &path)?;
    Ok(file)
}

impl Journal {
    /// Creates `dir` and a new journal in it, locked.
    pub fn create(dir: &Path) -> Result<Self, JournalError> {
        std::fs::create_dir_all(dir).map_err(io(dir))?;
        let path = dir.join(JOURNAL);
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(io(&path))?;
        lock(&file, &path)?;
        Ok(Self { file, path })
    }

    /// Opens an existing journal, locked, with its records.
    pub fn open(dir: &Path) -> Result<(Self, Vec<Record>), JournalError> {
        let path = dir.join(JOURNAL);
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&path)
            .map_err(io(&path))?;
        lock(&file, &path)?;
        let records = read(&path, &file)?;
        Ok((Self { file, path }, records))
    }

    pub fn append(&mut self, record: &Record) -> Result<(), JournalError> {
        let mut line = serde_json::to_string(record).expect("records serialize");
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(io(&self.path))?;
        self.file.sync_data().map_err(io(&self.path))
    }
}

/// The first record of a journal without locking it, to compare input hashes across runs.
pub fn read_header(dir: &Path) -> Result<Option<Record>, JournalError> {
    Ok(read_unlocked(dir)?.into_iter().next())
}

/// Every record of a journal without locking it, for read-only views of a run that may
/// still be live.
pub fn read_unlocked(dir: &Path) -> Result<Vec<Record>, JournalError> {
    let path = dir.join(JOURNAL);
    let file = File::open(&path).map_err(io(&path))?;
    read(&path, &file)
}

fn read(path: &Path, file: &File) -> Result<Vec<Record>, JournalError> {
    let lines: Vec<String> = BufReader::new(file)
        .lines()
        .collect::<Result<_, _>>()
        .map_err(io(path))?;
    let mut records = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        // A crash can cut the last line short; the attempt it held was never sent.
        match serde_json::from_str(line) {
            Ok(r) => records.push(r),
            Err(_) if i + 1 == lines.len() && !line.ends_with('}') => break,
            Err(e) => {
                return Err(JournalError::Corrupt {
                    path: path.to_path_buf(),
                    line: i + 1,
                    why: e.to_string(),
                });
            }
        }
    }
    Ok(records)
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("scope-journal-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn records_round_trip_and_file_is_private() {
        let d = dir("roundtrip");
        let records = [
            Record::Landed {
                row: 3,
                signature: "sig".into(),
            },
            Record::Done,
        ];
        {
            let mut j = Journal::create(&d).expect("create");
            for r in &records {
                j.append(r).expect("append");
            }
        }
        let (_, read) = Journal::open(&d).expect("open");
        assert_eq!(read, records);
        let mode = std::fs::metadata(d.join(JOURNAL))
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn second_writer_is_refused() {
        let d = dir("lock");
        let _held = Journal::create(&d).expect("create");
        assert!(matches!(Journal::open(&d), Err(JournalError::Locked(_))));
    }

    #[test]
    fn torn_last_line_is_dropped_but_corruption_is_not() {
        let d = dir("torn");
        drop(Journal::create(&d).expect("create"));
        let path = d.join(JOURNAL);
        std::fs::write(&path, "{\"t\":\"done\"}\n{\"t\":\"land").expect("write");
        let (_, read) = Journal::open(&d).expect("open");
        assert_eq!(read, [Record::Done]);
        std::fs::write(&path, "{\"t\":\"land\n{\"t\":\"done\"}\n").expect("write");
        assert!(matches!(
            Journal::open(&d),
            Err(JournalError::Corrupt { line: 1, .. })
        ));
        std::fs::write(&path, "{\"t\":\"nope\"}\n{\"t\":\"done\"}\n").expect("write");
        assert!(matches!(
            Journal::open(&d),
            Err(JournalError::Corrupt { line: 1, .. })
        ));
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
    }
}
