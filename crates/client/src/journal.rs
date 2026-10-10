//! Append-only run journal (docs/payer.md, What if the run crashes?): `runs/<run_id>/journal.jsonl`,
//! mode 0600, one writer holding an exclusive lock. Every record is fsynced before
//! the call returns, so an attempt is on disk before its transaction is sent. It
//! holds no secret and no plaintext amount; the amounts live in the input copy.

use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{BufReader, Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Journal layout written by this version. Older journals lack the field and read as 0.
pub const FORMAT: u32 = 1;
pub const JOURNAL: &str = "journal.jsonl";
pub const INPUT_COPY: &str = "input.csv";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Record {
    Run {
        /// Layout version, so a newer journal is refused instead of misread.
        #[serde(default)]
        format: u32,
        /// Genesis hash of the cluster the run pays on, hex; empty in runs that predate it.
        #[serde(default)]
        genesis: String,
        run_id: String,
        /// Hash of the input copy's bytes, which guards the copy against edits.
        input_sha256: String,
        /// Hash of the rows, mint and payer (`pay::input_key`), which the duplicate guard
        /// compares; empty in runs that predate it.
        #[serde(default)]
        input_key: String,
        mint: String,
        source: String,
        payer: String,
        /// Send order: a random permutation of row indexes, so it does not mirror the file.
        order: Vec<usize>,
        /// Amount openings come from the run secret, so receipts can be rebuilt. False in
        /// runs that predate it.
        #[serde(default)]
        derived_openings: bool,
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
    /// The run stopped on an error it cannot get past by itself; shown by `--status`.
    Halted {
        reason: String,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0} is locked by another run")]
    Locked(PathBuf),
    #[error("{0} was written by a newer scope (journal format {1}); upgrade scope")]
    NewerFormat(PathBuf, u32),
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
    file.sync_all().map_err(io(path))?;
    sync_parent(path)
}

/// Creates `dir` and any missing parents, readable only by the owner.
pub fn create_private_dir(dir: &Path) -> Result<(), JournalError> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io(dir))
}

/// Makes a new directory entry for `path` durable.
fn sync_parent(path: &Path) -> Result<(), JournalError> {
    let dir = path.parent().unwrap_or(Path::new("."));
    File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
}

/// Takes the exclusive lock on `dir/.lock`, creating both; released when the file drops.
pub fn lock_dir(dir: &Path) -> Result<File, JournalError> {
    create_private_dir(dir)?;
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
        create_private_dir(dir)?;
        let path = dir.join(JOURNAL);
        let file = OpenOptions::new()
            .append(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(io(&path))?;
        lock(&file, &path)?;
        sync_parent(&path)?;
        sync_parent(dir)?;
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
        let (records, keep) = read(&path, &file)?;
        repair_tail(&path, &file, keep)?;
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
    read(&path, &file).map(|(records, _)| records)
}

/// Reads the records and the byte length they occupy. A last line that does not parse
/// is a crash's torn write, whose attempt was never sent, so it is left out of both.
fn read(path: &Path, file: &File) -> Result<(Vec<Record>, u64), JournalError> {
    let mut data = Vec::new();
    BufReader::new(file)
        .read_to_end(&mut data)
        .map_err(io(path))?;
    let lines: Vec<&[u8]> = data.split_inclusive(|&b| b == b'\n').collect();
    let mut records = Vec::new();
    let mut keep = 0;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        match serde_json::from_slice(line) {
            Ok(r) => {
                records.push(r);
                keep += raw.len();
            }
            Err(_) if i + 1 == lines.len() && !line.ends_with(b"}") => break,
            Err(e) => {
                return Err(JournalError::Corrupt {
                    path: path.to_path_buf(),
                    line: i + 1,
                    why: e.to_string(),
                });
            }
        }
    }
    if let Some(Record::Run { format, .. }) = records.first()
        && *format > FORMAT
    {
        return Err(JournalError::NewerFormat(path.to_path_buf(), *format));
    }
    Ok((records, keep as u64))
}

/// Ends the file on a newline before anything is appended, so a new record never joins
/// the bytes a crash left behind. Everything after the last record `read` kept is cut
/// off; a complete record that lost only its newline gets one.
fn repair_tail(path: &Path, mut file: &File, keep: u64) -> Result<(), JournalError> {
    let len = file.metadata().map_err(io(path))?.len();
    if len > keep {
        file.set_len(keep).map_err(io(path))?;
    } else if len > 0 {
        let data = std::fs::read(path).map_err(io(path))?;
        if data.ends_with(b"\n") {
            return Ok(());
        }
        file.write_all(b"\n").map_err(io(path))?;
    } else {
        return Ok(());
    }
    file.sync_data().map_err(io(path))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex only, so every value has one encoding.
pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
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
    fn appends_after_a_torn_tail_stay_readable() {
        let d = dir("torn-append");
        drop(Journal::create(&d).expect("create"));
        let path = d.join(JOURNAL);
        let landed = Record::Landed {
            row: 1,
            signature: "sig".into(),
        };
        for (tail, kept) in [
            ("{\"t\":\"land", vec![Record::Done]),
            ("{\"t\":\"done\"}", vec![Record::Done, Record::Done]),
        ] {
            std::fs::write(&path, format!("{{\"t\":\"done\"}}\n{tail}")).expect("write");
            {
                let (mut j, read) = Journal::open(&d).expect("open");
                assert_eq!(read, kept);
                j.append(&landed).expect("append");
            }
            let (_, read) = Journal::open(&d).expect("reopen");
            assert_eq!(read, [kept, vec![landed.clone()]].concat());
        }
    }

    #[test]
    fn a_garbage_last_line_with_a_newline_is_cut_before_the_next_append() {
        let d = dir("garbage-tail");
        drop(Journal::create(&d).expect("create"));
        let path = d.join(JOURNAL);
        let landed = Record::Landed {
            row: 1,
            signature: "sig".into(),
        };
        std::fs::write(&path, "{\"t\":\"done\"}\nnot json at all\n").expect("write");
        {
            let (mut j, read) = Journal::open(&d).expect("open");
            assert_eq!(read, [Record::Done]);
            j.append(&landed).expect("append");
        }
        let (_, read) = Journal::open(&d).expect("reopen");
        assert_eq!(read, [Record::Done, landed]);
        assert_eq!(read_unlocked(&d).expect("unlocked").len(), 2);
    }

    #[test]
    fn journals_without_a_format_still_read_and_newer_ones_are_refused() {
        let d = dir("format");
        drop(Journal::create(&d).expect("create"));
        let path = d.join(JOURNAL);
        let old = r#"{"t":"run","run_id":"ab","input_sha256":"00","mint":"m","source":"s","payer":"p","order":[0]}"#;
        std::fs::write(&path, format!("{old}\n")).expect("write");
        let (_, read) = Journal::open(&d).expect("old journal opens");
        assert!(matches!(
            &read[0],
            Record::Run { format: 0, genesis, derived_openings: false, .. } if genesis.is_empty()
        ));
        let newer = old.replace(r#""run_id""#, r#""format":99,"run_id""#);
        std::fs::write(&path, format!("{newer}\n")).expect("write");
        assert!(matches!(
            Journal::open(&d),
            Err(JournalError::NewerFormat(_, 99))
        ));
        assert!(matches!(
            read_unlocked(&d),
            Err(JournalError::NewerFormat(_, 99))
        ));
    }

    #[test]
    fn run_directories_are_private() {
        let d = dir("private").join("runs").join("one");
        drop(Journal::create(&d).expect("create"));
        for dir in [d.clone(), d.parent().expect("parent").to_path_buf()] {
            let mode = std::fs::metadata(&dir).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "{}", dir.display());
        }
        let locked = dir("private-lock").join("runs");
        drop(lock_dir(&locked).expect("lock"));
        let mode = std::fs::metadata(&locked)
            .expect("meta")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn hex_round_trips() {
        assert_eq!(hex(&[0, 0xab, 0xff]), "00abff");
        assert_eq!(unhex("00abff"), Some(vec![0, 0xab, 0xff]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("zz"), None);
        assert_eq!(unhex("+f"), None);
        assert_eq!(unhex("AB"), None);
    }
}
