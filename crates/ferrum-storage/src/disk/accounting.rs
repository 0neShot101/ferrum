//! Checked byte ledger: temporary (reserved) and verified (installed) bytes are
//! accounted together against one managed ceiling (`PLAN.md` §0, §4).

use super::SpoolError;

/// Snapshot of the byte ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accounting {
    /// In-flight bytes, including detached operations and failed-cleanup charges.
    pub reserved: u64,
    /// Bytes of verified, installed objects.
    pub installed: u64,
    /// Managed ceiling for `reserved + installed`.
    pub ceiling: u64,
}

/// Mutable ledger; callers hold it under a `std::sync::Mutex` only for the
/// duration of one checked update, never across an await.
#[derive(Debug)]
pub(crate) struct Ledger {
    reserved: u64,
    installed: u64,
    ceiling: u64,
    closed: bool,
    metadata_reserved: u64,
    metadata_installed: u64,
    reservations: usize,
}

impl Ledger {
    pub(crate) fn new(ceiling: u64) -> Self {
        Self {
            reserved: 0,
            installed: 0,
            ceiling,
            closed: false,
            metadata_reserved: 0,
            metadata_installed: 0,
            reservations: 0,
        }
    }

    pub(crate) fn snapshot(&self) -> Accounting {
        Accounting {
            reserved: self.reserved,
            installed: self.installed,
            ceiling: self.ceiling,
        }
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
    }

    pub(crate) fn ensure_open(&self) -> Result<(), SpoolError> {
        if self.closed {
            Err(SpoolError::AdmissionClosed)
        } else {
            Ok(())
        }
    }

    fn used(&self) -> u64 {
        self.reserved.saturating_add(self.installed)
    }

    /// Adds `size` to the reserved bytes if the ceiling can hold it.
    pub(crate) fn reserve(&mut self, size: u64) -> Result<(), SpoolError> {
        self.ensure_open()?;
        let available = self.ceiling.saturating_sub(self.used());
        let fits = self
            .used()
            .checked_add(size)
            .is_some_and(|total| total <= self.ceiling);
        if !fits {
            return Err(SpoolError::CapacityExhausted {
                requested: size,
                available,
            });
        }
        let Some(reservations) = self.reservations.checked_add(1) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.reserved += size; // The checked total above proves this cannot overflow.
        self.reservations = reservations;
        Ok(())
    }

    /// Returns reserved bytes that were never installed.
    pub(crate) fn release(&mut self, size: u64) {
        match (
            self.reserved.checked_sub(size),
            self.reservations.checked_sub(1),
        ) {
            (Some(remaining), Some(reservations)) => {
                self.reserved = remaining;
                self.reservations = reservations;
            }
            _ => {
                tracing::error!(
                    reserved = self.reserved,
                    size,
                    "ledger reservation release invariant violated"
                );
                self.close();
            }
        }
    }

    /// Moves `size` bytes from reserved to installed.
    pub(crate) fn install(&mut self, size: u64) -> Result<(), SpoolError> {
        self.ensure_open()?;
        let Some(reserved) = self.reserved.checked_sub(size) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        let Some(installed) = self.installed.checked_add(size) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        let Some(reservations) = self.reservations.checked_sub(1) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.reserved = reserved;
        self.installed = installed;
        self.reservations = reservations;
        Ok(())
    }

    pub(crate) fn reserve_class(&mut self, size: u64, metadata: bool) -> Result<(), SpoolError> {
        self.reserve(size)?;
        if metadata {
            self.metadata_reserved += size;
        }
        Ok(())
    }

    pub(crate) fn release_class(&mut self, size: u64, metadata: bool) {
        let remaining = if metadata {
            self.metadata_reserved.checked_sub(size)
        } else {
            Some(self.metadata_reserved)
        };
        let Some(remaining) = remaining else {
            self.close();
            return;
        };
        self.release(size);
        self.metadata_reserved = remaining;
    }

    pub(crate) fn install_as(
        &mut self,
        size: u64,
        reserved_metadata: bool,
        installed_metadata: bool,
    ) -> Result<(), SpoolError> {
        let reserved = if reserved_metadata {
            self.metadata_reserved.checked_sub(size)
        } else {
            Some(self.metadata_reserved)
        };
        let installed = if installed_metadata {
            self.metadata_installed.checked_add(size)
        } else {
            Some(self.metadata_installed)
        };
        let (Some(reserved), Some(installed)) = (reserved, installed) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.install(size)?;
        self.metadata_reserved = reserved;
        self.metadata_installed = installed;
        Ok(())
    }

    pub(crate) fn require_package_retention(&mut self, size: u64) -> Result<(), SpoolError> {
        let Some(remaining) = self.metadata_installed.checked_sub(size) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.metadata_installed = remaining;
        Ok(())
    }

    pub(crate) fn remove_installed(&mut self, size: u64, metadata: bool) -> Result<(), SpoolError> {
        let installed = self.installed.checked_sub(size);
        let metadata_installed = if metadata {
            self.metadata_installed.checked_sub(size)
        } else {
            Some(self.metadata_installed)
        };
        let (Some(installed), Some(metadata_installed)) = (installed, metadata_installed) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.installed = installed;
        self.metadata_installed = metadata_installed;
        Ok(())
    }

    pub(crate) fn restore_installed(
        &mut self,
        size: u64,
        metadata: bool,
    ) -> Result<(), SpoolError> {
        let installed = self.installed.checked_add(size);
        let metadata_installed = if metadata {
            self.metadata_installed.checked_add(size)
        } else {
            Some(self.metadata_installed)
        };
        let (Some(installed), Some(metadata_installed)) = (installed, metadata_installed) else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.installed = installed;
        self.metadata_installed = metadata_installed;
        Ok(())
    }

    pub(crate) fn reservation_count(&self) -> usize {
        self.reservations
    }
    pub(crate) fn metadata_reserved(&self) -> u64 {
        self.metadata_reserved
    }
    pub(crate) fn metadata_installed(&self) -> u64 {
        self.metadata_installed
    }

    pub(crate) fn restore_reservation(
        &mut self,
        size: u64,
        metadata: bool,
    ) -> Result<(), SpoolError> {
        let reserved = self.reserved.checked_add(size);
        let reservations = self.reservations.checked_add(1);
        let metadata_reserved = if metadata {
            self.metadata_reserved.checked_add(size)
        } else {
            Some(self.metadata_reserved)
        };
        let (Some(reserved), Some(reservations), Some(metadata_reserved)) =
            (reserved, reservations, metadata_reserved)
        else {
            self.close();
            return Err(SpoolError::AdmissionClosed);
        };
        self.reserved = reserved;
        self.reservations = reservations;
        self.metadata_reserved = metadata_reserved;
        Ok(())
    }
}

/// Physical free bytes must cover outstanding reservations and the new object.
/// Subtraction avoids overflow at u64::MAX and preserves the exact boundary.
pub(super) fn check_physical(
    available: u64,
    reserved: u64,
    requested: u64,
) -> Result<(), SpoolError> {
    if reserved > available || requested > available - reserved {
        return Err(SpoolError::CapacityExhausted {
            requested,
            available: available.saturating_sub(reserved),
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn reserve_refuses_beyond_ceiling_and_reports_available() {
        let mut ledger = Ledger::new(100);
        ledger.reserve(60).expect("60 fits under 100");
        let exhausted = ledger.reserve(41);
        assert!(
            matches!(
                exhausted,
                Err(SpoolError::CapacityExhausted {
                    requested: 41,
                    available: 40,
                })
            ),
            "got {exhausted:?}"
        );
        ledger.reserve(40).expect("exactly the remainder fits");
    }

    #[test]
    fn reserve_near_u64_max_does_not_overflow() {
        let mut ledger = Ledger::new(u64::MAX);
        ledger.reserve(u64::MAX - 1).expect("fits");
        assert!(matches!(
            ledger.reserve(2),
            Err(SpoolError::CapacityExhausted { .. })
        ));
    }

    #[test]
    fn install_moves_bytes_and_release_returns_them() {
        let mut ledger = Ledger::new(100);
        ledger.reserve(30).expect("fits");
        ledger.reserve(20).expect("fits");
        ledger.install(30).expect("reservation installed");
        ledger.release(20);
        assert_eq!(
            ledger.snapshot(),
            Accounting {
                reserved: 0,
                installed: 30,
                ceiling: 100
            }
        );
    }

    #[test]
    fn physical_admission_checks_exact_capacity_and_overflow() {
        assert!(check_physical(100, 60, 40).is_ok());
        assert!(check_physical(100, 60, 41).is_err());
        assert!(check_physical(100, 101, 0).is_err());
        assert!(check_physical(0, 0, 0).is_ok());
        assert!(check_physical(0, 0, 1).is_err());
        assert!(check_physical(u64::MAX, u64::MAX, 0).is_ok());
        assert!(check_physical(u64::MAX, u64::MAX, 1).is_err());
        assert!(check_physical(u64::MAX, u64::MAX - 1, 1).is_ok());
    }

    #[test]
    fn ledger_mismatch_preserves_charge_and_closes_admission() {
        let mut ledger = Ledger::new(100);
        ledger.reserve(30).expect("fits");
        assert!(ledger.install(31).is_err());
        assert_eq!(ledger.snapshot().reserved, 30);
        assert_eq!(ledger.snapshot().installed, 0);
        assert!(matches!(
            ledger.reserve(1),
            Err(SpoolError::AdmissionClosed)
        ));
    }
}
