use std::fs::{self, File, Metadata};
use std::io::{self, Read, Seek};
use std::path::{Path, PathBuf};

use crate::Failure;

pub(crate) const METADATA_CAP: u64 = 32 * 1024 * 1024;
pub(crate) const PACKAGE_CAP: u64 = 8 * 1024 * 1024 * 1024;

pub(crate) fn open_metadata(path: &Path) -> Result<Input, Failure> {
    open(path, METADATA_CAP, None).map_err(|_| Failure::Input)
}

pub(crate) fn open_package(path: &Path, expected_size: u64) -> Result<Input, Failure> {
    open(path, PACKAGE_CAP, Some(expected_size)).map_err(|_| Failure::PackageInput)
}

fn open(path: &Path, limit: u64, expected_size: Option<u64>) -> io::Result<Input> {
    if expected_size.is_some_and(|size| size > limit) {
        return Err(io::Error::other("input size exceeds its limit"));
    }
    // Check before open as well: opening an existing FIFO must not block.
    // Operator-owned keyring symlinks remain supported, but their resolved
    // regular-file identity must agree before open and after verification.
    let before = fs::metadata(path)?;
    if !before.is_file()
        || before.len() > limit
        || expected_size.is_some_and(|size| before.len() != size)
    {
        return Err(io::Error::other(
            "input is not a regular file of the required size",
        ));
    }
    let inner = File::open(path)?;
    let snapshot = inner.metadata()?;
    if !same_file(&before, &snapshot) {
        return Err(io::Error::other("input changed while opening"));
    }
    Ok(Input {
        inner,
        path: path.to_owned(),
        remaining: snapshot.len(),
        snapshot,
    })
}

pub(crate) struct Input {
    inner: File,
    path: PathBuf,
    snapshot: Metadata,
    remaining: u64,
}

impl Input {
    pub(crate) fn rewind(&mut self) -> Result<(), Failure> {
        self.inner.rewind().map_err(|_| Failure::Input)?;
        self.remaining = self.snapshot.len();
        Ok(())
    }

    pub(crate) fn verify_unchanged(&self) -> Result<(), Failure> {
        let current = self.inner.metadata().map_err(|_| Failure::InputChanged)?;
        let resolved = fs::metadata(&self.path).map_err(|_| Failure::InputChanged)?;
        if !same_file(&self.snapshot, &current) || !same_file(&self.snapshot, &resolved) {
            return Err(Failure::InputChanged);
        }
        Ok(())
    }

    pub(crate) fn finish(&mut self) -> Result<(), Failure> {
        // The verifier must have consumed the entire admitted representation,
        // including an EOF probe; a valid signature cannot excuse truncation.
        if self.remaining != 0 || self.read(&mut [0]).map_err(|_| Failure::InputChanged)? != 0 {
            return Err(Failure::InputChanged);
        }
        Ok(())
    }
}

fn same_file(before: &Metadata, after: &Metadata) -> bool {
    let (Ok(before_modified), Ok(after_modified)) = (before.modified(), after.modified()) else {
        return false;
    };
    if !after.is_file()
        || before.len() != after.len()
        || before_modified != after_modified
        || before.created().ok() != after.created().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
        {
            return false;
        }
    }
    true
}

impl Read for Input {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut overflow = [0];
            return match self.inner.read(&mut overflow)? {
                0 => {
                    self.verify_unchanged().map_err(io::Error::other)?;
                    Ok(0)
                }
                _ => Err(io::Error::other("input grew beyond its admitted size")),
            };
        }
        let limit = buffer
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut buffer[..limit])?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "input was truncated",
            ));
        }
        let consumed = u64::try_from(count).map_err(io::Error::other)?;
        self.remaining = self
            .remaining
            .checked_sub(consumed)
            .ok_or_else(|| io::Error::other("input byte count overflow"))?;
        Ok(count)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn changed_or_replaced_package_input_is_rejected() {
        let directory = tempfile::tempdir().expect("input directory");
        let path = directory.path().join("package");
        fs::write(&path, b"original").expect("original input");
        let mut input = open_package(&path, 8).expect("admitted package");
        let mut contents = [0; 8];
        input
            .read_exact(&mut contents)
            .expect("stream original bytes");
        File::options()
            .append(true)
            .open(&path)
            .expect("append input")
            .write_all(b"extra")
            .expect("grow input");
        assert!(input.finish().is_err(), "growth cannot be ignored at EOF");

        fs::write(&path, b"original").expect("restore input");
        let input = open_package(&path, 8).expect("admitted package");
        fs::write(&path, b"replaced").expect("same-length mutation");
        File::options()
            .write(true)
            .open(&path)
            .expect("modified input")
            .set_modified(std::time::UNIX_EPOCH)
            .expect("distinct modification timestamp");
        assert!(
            input.verify_unchanged().is_err(),
            "same-length mutation must reject"
        );
    }

    #[test]
    fn shortened_package_input_is_not_successful_eof() {
        let directory = tempfile::tempdir().expect("input directory");
        let path = directory.path().join("package");
        fs::write(&path, b"original").expect("original input");
        let mut input = open_package(&path, 8).expect("admitted package");
        File::options()
            .write(true)
            .open(&path)
            .expect("truncate input")
            .set_len(4)
            .expect("shorten input");
        let mut contents = [0; 8];
        assert!(input.read_exact(&mut contents).is_err());
        assert!(input.finish().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn replacing_the_input_path_does_not_authenticate_the_replacement() {
        let directory = tempfile::tempdir().expect("input directory");
        let path = directory.path().join("package");
        fs::write(&path, b"original").expect("original input");
        let mut input = open_package(&path, 8).expect("admitted package");
        let mut contents = [0; 8];
        input
            .read_exact(&mut contents)
            .expect("read original input");
        fs::rename(&path, directory.path().join("previous")).expect("move original input");
        fs::write(&path, b"original").expect("same-content replacement");
        assert!(
            input.finish().is_err(),
            "success must still refer to the same file"
        );
    }
}
