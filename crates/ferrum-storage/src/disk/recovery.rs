//! Startup runs exclusively and before the Spool escapes. First charge every
//! persisted reservation and physical file, then clean incomplete/untrusted
//! names, and only finally enable cold admission. No filename authenticates
//! an object and no directory-sized collection is retained in memory.

use std::fs::{self, File};
use std::io;
use std::path::Path;

use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};

use super::{
    Entry, ReservationClass, SpoolError, SpoolInner, VerifiedObject, lock_unpoisoned, writer,
};

pub(super) fn catalog_bytes(root: &Path) -> Result<u64, SpoolError> {
    let mut bytes = 0u64;
    for name in [
        "state.sqlite",
        "state.sqlite-wal",
        "state.sqlite-shm",
        ".ferrum-durable-spool",
        "lock",
    ] {
        match fs::symlink_metadata(root.join(name)) {
            Ok(metadata) if metadata.is_file() => {
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or(SpoolError::AdmissionClosed)?;
            }
            Ok(_) => {
                return Err(SpoolError::UnsafeDirectory(format!(
                    "unexpected catalog entry type: {name}"
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(bytes)
}

fn walk(
    directory: &Path,
    depth: usize,
    action: &mut impl FnMut(&Path, u64) -> Result<(), SpoolError>,
) -> Result<(), SpoolError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_file() {
            action(&entry.path(), entry.metadata()?.len())?;
        } else if kind.is_dir() && depth < 5 {
            walk(&entry.path(), depth + 1, action)?;
        } else {
            return Err(SpoolError::UnsafeDirectory(format!(
                "unexpected file or directory depth: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn authenticated_resident(
    spool: &SpoolInner,
    path: &Path,
    size: u64,
) -> Result<Option<crate::catalog::Resident>, SpoolError> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Ok(None);
    };
    let Ok(digest) = Sha256Digest::from_hex(name) else {
        return Ok(None);
    };
    // Even an otherwise valid digest is not an allowed alternative pathname.
    if path != spool.object_path(&digest) {
        return Ok(None);
    }
    let catalog = spool.catalog().ok_or(SpoolError::AdmissionClosed)?;
    let resident = catalog.object(ObjectIdentity {
        sha256: digest,
        size,
    })?;
    Ok(resident.filter(|row| row.state == 1))
}

pub(super) fn reconcile(spool: &SpoolInner) -> Result<(), SpoolError> {
    let config = spool.durable.as_ref().ok_or(SpoolError::AdmissionClosed)?;
    let catalog = spool.catalog().ok_or(SpoolError::AdmissionClosed)?;
    let mut cursor = None;
    loop {
        let reservations = catalog.reservations(cursor)?;
        if reservations.is_empty() {
            break;
        }
        for reservation in &reservations {
            let class = ReservationClass::from_sql(reservation.class)?;
            lock_unpoisoned(&spool.lifetime.ledger)
                .restore_reservation(reservation.size, class.metadata())?;
        }
        cursor = reservations.last().map(|row| row.id.clone());
    }
    // Charge files before unlinking any. Unknown/incomplete files receive a
    // separate conservative charge even if a reservation also covers the inode.
    for directory in [spool.temporary_dir(), spool.root.join("objects")] {
        walk(&directory, 0, &mut |_, size| {
            lock_unpoisoned(&spool.lifetime.ledger).restore_installed(size, false)
        })?;
    }
    walk(&spool.temporary_dir(), 0, &mut |path, size| {
        fs::remove_file(path)?;
        writer::fsync_directory(path.parent().ok_or(SpoolError::AdmissionClosed)?)?;
        lock_unpoisoned(&spool.lifetime.ledger).remove_installed(size, false)
    })?;
    walk(&spool.root.join("objects"), 0, &mut |path, size| {
        if let Some(row) = authenticated_resident(spool, path, size)? {
            let class = ReservationClass::from_sql(row.class)?;
            let mut registry = lock_unpoisoned(&spool.installed);
            if registry.entries.len() >= config.max_entries {
                return Err(SpoolError::CapacityExhausted {
                    requested: 1,
                    available: 0,
                });
            }
            let object = VerifiedObject::open(spool, row.identity, path.to_owned())?;
            if class.metadata() {
                let mut ledger = lock_unpoisoned(&spool.lifetime.ledger);
                ledger.remove_installed(size, false)?;
                ledger.restore_installed(size, true)?;
            }
            registry.policy.insert(row.identity);
            registry.entries.insert(
                row.identity,
                Entry {
                    object,
                    class,
                    durable: row.durable,
                    reconstructible: row.reconstructible,
                    generation_references: row.generation_references,
                    pins: [0; 3],
                    evicting: false,
                },
            );
        } else {
            fs::remove_file(path)?;
            writer::fsync_directory(path.parent().ok_or(SpoolError::AdmissionClosed)?)?;
            lock_unpoisoned(&spool.lifetime.ledger).remove_installed(size, false)?;
        }
        Ok(())
    })?;
    // Persisted residency may describe a lost file or an interrupted eviction.
    // It cannot authorize a hit until an actual read-only handle was acquired.
    let mut cursor = None;
    loop {
        let rows = catalog.residents(cursor)?;
        if rows.is_empty() {
            break;
        }
        for row in &rows {
            if !lock_unpoisoned(&spool.installed)
                .entries
                .contains_key(&row.identity)
            {
                catalog.set_residency(row.identity, 0)?;
            }
        }
        cursor = rows.last().map(|row| row.identity.sha256.to_hex());
    }
    let mut cursor = None;
    loop {
        let reservations = catalog.reservations(cursor)?;
        if reservations.is_empty() {
            break;
        }
        for reservation in &reservations {
            catalog.release(reservation.id.clone())?;
            let class = ReservationClass::from_sql(reservation.class)?;
            lock_unpoisoned(&spool.lifetime.ledger)
                .release_class(reservation.size, class.metadata());
        }
        cursor = reservations.last().map(|row| row.id.clone());
    }
    File::open(&spool.root)?.sync_all()?;
    let ledger = lock_unpoisoned(&spool.lifetime.ledger);
    let snapshot = ledger.snapshot();
    let catalog_bytes = catalog_bytes(&spool.root)?;
    let total = snapshot
        .installed
        .checked_add(snapshot.reserved)
        .and_then(|bytes| bytes.checked_add(catalog_bytes))
        .ok_or(SpoolError::AdmissionClosed)?;
    if total > snapshot.ceiling
        || catalog_bytes > config.catalog_ceiling
        || ledger.metadata_installed() > config.metadata_ceiling
    {
        return Err(SpoolError::CapacityExhausted {
            requested: total,
            available: snapshot.ceiling,
        });
    }
    Ok(())
}
