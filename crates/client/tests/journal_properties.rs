//! A journal survives a crash at any byte: it reopens with a prefix of what was written,
//! and appends after the repair read back.

use proptest::prelude::*;
use scope_client::journal::{JOURNAL, Journal, Record};
use std::path::PathBuf;

fn dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scope-journal-prop-{tag}-{}-{:x}",
        std::process::id(),
        rand_suffix()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

/// Removes the directory even when an assertion fails.
struct Cleanup(PathBuf);

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn landed(row: usize, signature: &str) -> Record {
    Record::Landed {
        row,
        signature: signature.into(),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn a_cut_at_any_byte_reopens_with_a_prefix_and_accepts_appends(
        sigs in proptest::collection::vec("[A-Za-z0-9]{1,20}", 1..6),
        cut in any::<proptest::sample::Index>(),
    ) {
        let d = dir("cut");
        let _cleanup = Cleanup(d.clone());
        let written: Vec<Record> = sigs.iter().enumerate().map(|(i, s)| landed(i, s)).collect();
        {
            let mut j = Journal::create(&d).unwrap();
            for r in &written {
                j.append(r).unwrap();
            }
        }
        let path = d.join(JOURNAL);
        let bytes = std::fs::read(&path).unwrap();
        let keep = cut.index(bytes.len() + 1);
        std::fs::write(&path, &bytes[..keep]).unwrap();

        let (mut j, read) = Journal::open(&d).unwrap();
        prop_assert!(written.starts_with(&read), "{read:?}");
        let extra = landed(99, "after");
        j.append(&extra).unwrap();
        drop(j);
        let (_, again) = Journal::open(&d).unwrap();
        prop_assert_eq!(again, [read, vec![extra]].concat());
    }

    #[test]
    fn garbage_after_the_records_never_panics_and_a_repaired_journal_stays_usable(
        garbage in proptest::collection::vec(any::<u8>(), 0..40),
        newline in any::<bool>(),
    ) {
        let d = dir("garbage");
        let _cleanup = Cleanup(d.clone());
        {
            let mut j = Journal::create(&d).unwrap();
            j.append(&landed(0, "first")).unwrap();
        }
        let path = d.join(JOURNAL);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend(&garbage);
        if newline {
            bytes.push(b'\n');
        }
        std::fs::write(&path, bytes).unwrap();

        // The reader cuts a last line that has no newline and does not end in `}`: a crash
        // stops mid-record, so a tail that closes a brace is damage, not a torn write.
        let torn = !newline && !garbage.contains(&b'\n') && !garbage.ends_with(b"}");
        let closed = !newline && !garbage.contains(&b'\n') && garbage.ends_with(b"}");
        match Journal::open(&d) {
            Ok((mut j, _)) => {
                prop_assert!(!closed, "a tail ending in a brace is refused");
                j.append(&landed(1, "next")).unwrap();
                drop(j);
                prop_assert!(Journal::open(&d).is_ok(), "an accepted journal stays openable");
            }
            Err(error) => prop_assert!(!torn, "a torn tail must reopen: {error:?}"),
        }
    }
}

fn journal_with_tail(tag: &str, tail: &[u8]) -> (PathBuf, Cleanup) {
    let d = dir(tag);
    let cleanup = Cleanup(d.clone());
    {
        let mut j = Journal::create(&d).expect("create");
        j.append(&landed(0, "first")).expect("append");
    }
    let path = d.join(JOURNAL);
    let mut bytes = std::fs::read(&path).expect("read");
    bytes.extend(tail);
    std::fs::write(&path, bytes).expect("write");
    (d, cleanup)
}

/// The reader refuses a last line that ends in `}`; only a line cut off mid-record is a
/// torn write.
#[test]
fn a_tail_that_closes_a_brace_is_corrupt_and_a_cut_record_is_repaired() {
    for tail in [&b"}"[..], b"x}", b"{\"t\":\"landed\"}}"] {
        let (d, _cleanup) = journal_with_tail("brace", tail);
        assert!(
            matches!(
                Journal::open(&d),
                Err(scope_client::journal::JournalError::Corrupt { .. })
            ),
            "{}",
            String::from_utf8_lossy(tail)
        );
    }
    for tail in [&b"{\"t\":\"land"[..], b"{", b"\x00\xff"] {
        let (d, _cleanup) = journal_with_tail("torn", tail);
        let (mut j, read) = Journal::open(&d).expect("a torn tail reopens");
        assert_eq!(read, [landed(0, "first")]);
        j.append(&landed(1, "next")).expect("append");
        drop(j);
        let (_, again) = Journal::open(&d).expect("reopen");
        assert_eq!(again, [landed(0, "first"), landed(1, "next")]);
    }
}
