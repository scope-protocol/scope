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

        // A torn tail has no newline, so it is always cut instead of refused.
        let torn = !newline && !garbage.contains(&b'\n');
        match Journal::open(&d) {
            Ok((mut j, _)) => {
                j.append(&landed(1, "next")).unwrap();
                drop(j);
                prop_assert!(Journal::open(&d).is_ok(), "an accepted journal stays openable");
            }
            Err(error) => prop_assert!(!torn, "a torn tail must reopen: {error:?}"),
        }
    }
}
