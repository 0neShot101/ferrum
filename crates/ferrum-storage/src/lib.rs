//! Ferrum verified object storage and bounded S3 transport.
//!
//! The disk owner reserves bytes before writes and installs only fully verified,
//! fsynced objects. Fixture mode owns and clears an exclusive test directory;
//! durable mode reconciles its SQLite catalog before admitting new work.
//! Reader and operation leases preserve file accounting and eviction safety.

pub mod backup;
pub mod budget;
pub mod capture;
pub mod catalog;
pub mod checkpoint;
pub mod disk;
mod eviction;
pub mod gc;
pub mod recovery;
#[cfg(any(test, feature = "test-harness"))]
pub mod replay;
pub mod s3;
pub mod upload;

pub use disk::{
    Accounting, DurableSpoolConfig, ObjectPin, ObjectStream, PinKind, Reservation,
    ReservationClass, Spool, SpoolConfig, SpoolError, SpoolWriter, StorageUsage, VerifiedObject,
};
