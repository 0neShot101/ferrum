//! Exclusive ownership and startup cleanup of the fixture spool directory
//! (`PLAN.md` §0): the marker proves the directory is fixture-only, the
//! `flock` proves no other holder is alive, and cleanup removes only regular
//! files below `temporary/` and `objects/`.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

use super::SpoolError;

pub(crate) const MARKER_FILE: &str = ".ferrum-fixture-spool";
pub(crate) const LOCK_FILE: &str = "lock";
pub(crate) const TEMPORARY_DIR: &str = "temporary";
pub(crate) const OBJECTS_DIR: &str = "objects";
const DURABLE_MARKER: &str = ".ferrum-durable-spool";

/// Production ownership is deliberately incompatible with fixture cleanup.
pub(crate) fn take_durable_ownership(
    root: &Path,
) -> Result<(fd_lock::RwLock<File>, bool), SpoolError> {
    create_root_durably(root)?;
    let mut marker = false;
    let mut entries = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        entries = true;
        let kind = entry.file_type()?;
        let name = entry.file_name();
        let directory = match name.to_str() {
            Some(DURABLE_MARKER) => {
                marker = true;
                false
            }
            Some(LOCK_FILE | "state.sqlite" | "state.sqlite-wal" | "state.sqlite-shm") => false,
            Some(TEMPORARY_DIR | OBJECTS_DIR) => true,
            _ => {
                return Err(unsafe_directory(
                    &entry.path(),
                    "unexpected durable store entry",
                ));
            }
        };
        if kind.is_symlink() || kind.is_dir() != directory || (!directory && !kind.is_file()) {
            return Err(unsafe_directory(
                &entry.path(),
                "unexpected durable entry type",
            ));
        }
    }
    if entries && !marker {
        return Err(unsafe_directory(
            root,
            "non-empty directory without durable ownership marker",
        ));
    }
    let lock = acquire_lock(root)?;
    if marker && !root.join("state.sqlite").is_file() {
        return Err(unsafe_directory(
            root,
            "durable catalog is missing; authenticated recovery is required",
        ));
    }
    if !marker {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(DURABLE_MARKER))?;
        file.write_all(b"ferrum durable local store v1\n")?;
        file.sync_all()?;
        File::open(root)?.sync_all()?;
    }
    for directory in [
        root.join(TEMPORARY_DIR),
        root.join(OBJECTS_DIR),
        root.join(OBJECTS_DIR).join("sha256"),
    ] {
        create_dir_if_absent(&directory)?;
    }
    Ok((lock, !marker))
}

fn create_root_durably(path: &Path) -> Result<(), SpoolError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            File::open(path)?.sync_all()?;
            Ok(())
        }
        Ok(_) => Err(unsafe_directory(path, "expected a plain directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                create_root_durably(parent)?;
            }
            create_dir_if_absent(path)
        }
        Err(error) => Err(error.into()),
    }
}

/// Deepest directory nesting accepted below `objects/`
/// (`objects/sha256/aa/bb/<hex>`), with slack for layout changes.
const MAX_OBJECT_DEPTH: usize = 6;

/// Validates, locks and cleans `root`, returning the lock whose descriptor
/// must stay open for as long as ownership is required.
pub(crate) fn take_ownership(root: &Path) -> Result<fd_lock::RwLock<File>, SpoolError> {
    ensure_root_directory(root)?;
    validate_root_entries(root)?;
    let lock = acquire_lock(root)?;
    write_marker_if_absent(root)?;
    let temporary = root.join(TEMPORARY_DIR);
    clean_regular_files(&temporary, 0)?;
    create_dir_if_absent(&temporary)?;
    let objects = root.join(OBJECTS_DIR);
    clean_regular_files(&objects, 0)?;
    create_dir_if_absent(&objects)?;
    create_dir_if_absent(&objects.join("sha256"))?;
    Ok(lock)
}

fn ensure_root_directory(root: &Path) -> Result<(), SpoolError> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(()),
        Ok(_) => Err(unsafe_directory(
            root,
            "root is not a directory (or is a symlink)",
        )),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(fs::create_dir_all(root)?),
        Err(error) => Err(SpoolError::Io(error)),
    }
}

/// A non-empty root must carry the marker and contain only spool entries of
/// the expected kind; nothing is modified here.
fn validate_root_entries(root: &Path) -> Result<(), SpoolError> {
    let mut has_marker = false;
    let mut has_entries = false;
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        has_entries = true;
        let file_type = entry.file_type()?;
        let name = entry.file_name();
        let expected_dir = match name.to_str() {
            Some(MARKER_FILE) => {
                has_marker = true;
                false
            }
            Some(LOCK_FILE) => false,
            Some(TEMPORARY_DIR | OBJECTS_DIR) => true,
            _ => {
                return Err(unsafe_directory(
                    root,
                    &format!("unexpected entry {}", name.to_string_lossy()),
                ));
            }
        };
        if file_type.is_symlink() || file_type.is_dir() != expected_dir {
            return Err(unsafe_directory(
                root,
                &format!("entry {} has an unexpected type", name.to_string_lossy()),
            ));
        }
    }
    if has_entries && !has_marker {
        return Err(unsafe_directory(
            root,
            "non-empty directory without the fixture ownership marker",
        ));
    }
    Ok(())
}

fn acquire_lock(root: &Path) -> Result<fd_lock::RwLock<File>, SpoolError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(root.join(LOCK_FILE))?;
    let mut lock = fd_lock::RwLock::new(file);
    match lock.try_write() {
        // The guard only borrows the lock; the flock itself is released when
        // the descriptor closes, which happens when the owning `Spool` drops.
        Ok(guard) => std::mem::forget(guard),
        Err(error) if error.kind() == ErrorKind::WouldBlock => {
            return Err(SpoolError::NotExclusive(root.display().to_string()));
        }
        Err(error) => return Err(SpoolError::Io(error)),
    }
    Ok(lock)
}

fn write_marker_if_absent(root: &Path) -> Result<(), SpoolError> {
    let path = root.join(MARKER_FILE);
    let mut file = match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => return Ok(()),
        Err(error) => return Err(SpoolError::Io(error)),
    };
    file.write_all(b"ferrum fixture spool: contents are deleted at startup\n")?;
    file.sync_all()?;
    File::open(root)?.sync_all()?;
    Ok(())
}

/// Removes regular files below `directory`, descending into plain
/// subdirectories; symlinks and special files refuse startup.
fn clean_regular_files(directory: &Path, depth: usize) -> Result<(), SpoolError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(SpoolError::Io(error)),
    };
    for entry in entries {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_file() {
            fs::remove_file(&path)?;
            tracing::debug!(path = %path.display(), "removed leftover spool file");
        } else if file_type.is_dir() && depth < MAX_OBJECT_DEPTH {
            clean_regular_files(&path, depth.saturating_add(1))?;
        } else {
            return Err(unsafe_directory(
                &path,
                "not a regular file or a plain directory within the expected depth",
            ));
        }
    }
    Ok(())
}

fn create_dir_if_absent(path: &Path) -> Result<(), SpoolError> {
    match fs::create_dir(path) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            if !fs::symlink_metadata(path)?.is_dir() {
                return Err(unsafe_directory(path, "expected a plain directory"));
            }
        }
        Err(error) => return Err(SpoolError::Io(error)),
    }
    File::open(path)?.sync_all()?;
    if let Some(parent) = path.parent() {
        File::open(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        })?
        .sync_all()?;
    }
    Ok(())
}

fn unsafe_directory(path: &Path, reason: &str) -> SpoolError {
    SpoolError::UnsafeDirectory(format!("{}: {reason}", path.display()))
}
