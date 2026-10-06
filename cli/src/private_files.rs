use anyhow::Context;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

pub(super) fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

pub(super) fn create_parent(path: &Path) -> io::Result<()> {
    let mut directory = parent(path);
    let mut ancestors = Vec::new();
    while !directory.exists() {
        directory = parent(directory);
        ancestors.push(directory);
    }
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent(path))?;
    for directory in ancestors {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

pub(super) fn validate(file: &File, path: &Path) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a regular file with owner-only permissions (chmod 600)",
                path.display()
            ),
        ));
    }
    Ok(())
}

pub(super) fn create(
    path: &Path,
    write: impl FnOnce(&mut File) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    create_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| {
            format!(
                "creating {}; existing files are never overwritten",
                path.display()
            )
        })?;
    let result = write(&mut file).and_then(|()| {
        file.sync_all()?;
        File::open(parent(path))?.sync_all()?;
        Ok(())
    });
    if result.is_err() {
        drop(file);
        let _ = fs::remove_file(path);
    }
    result
}

#[cfg(test)]
pub(super) fn test_directory() -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let directory = std::env::temp_dir().join(format!(
        "scope-cli-files-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .expect("directory");
    directory
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn failed_writes_remove_only_the_new_file() {
        let dir = test_directory();
        let path = dir.join("partial.key");
        assert!(
            create(&path, |file| {
                file.write_all(b"partial")?;
                anyhow::bail!("write interrupted")
            })
            .is_err()
        );
        assert!(!path.exists());
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
