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
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn garbage_after_the_records_never_panics_and_a_repaired_journal_stays_usable(
        garbage in proptest::collection::vec(any::<u8>(), 0..40),
        newline in any::<bool>(),
    ) {
        let d = dir("garbage");
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

        if let Ok((mut j, _)) = Journal::open(&d) {
            j.append(&landed(1, "next")).unwrap();
            drop(j);
            prop_assert!(Journal::open(&d).is_ok(), "an accepted journal stays openable");
        }
        let _ = std::fs::remove_dir_all(&d);
    }
}
