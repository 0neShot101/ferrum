//! Persistent-mode consumers must never mistake missing or corrupt catalog
//! authority for a fresh bootstrap and delete the surviving object files.

#![allow(clippy::expect_used)]

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use bytes::Bytes;
use ferrum_apt::digest::{ObjectIdentity, Sha256Digest};
use ferrum_storage::disk::{DurableSpoolConfig, Spool};
use rusqlite::Connection;

fn config(root: &Path) -> DurableSpoolConfig {
    let mut config = DurableSpoolConfig::new(root.to_owned());
    config.spool.managed_ceiling = 32 * 1024 * 1024;
    config.spool.max_object_size = 1024 * 1024;
    config.spool.io_workers = 2;
    config.free_space_floor = 0;
    config.temporary_ceiling = 4 * 1024 * 1024;
    config.metadata_temporary_reserve = 1024 * 1024;
    config.metadata_ceiling = 8 * 1024 * 1024;
    config.catalog_ceiling = 16 * 1024 * 1024;
    config.max_entries = 128;
    config.catalog_memory_budget = 32 * 1024 * 1024;
    config.database_queue = 8;
    config.eviction_high_watermark = 24 * 1024 * 1024;
    config.eviction_low_watermark = 20 * 1024 * 1024;
    config
}

#[tokio::test]
async fn existing_empty_truncated_missing_and_incompatible_catalogs_preserve_all_files() {
    for corruption in ["empty", "truncated", "missing", "version", "schema"] {
        let root = tempfile::tempdir().expect("temporary directory");
        let config = config(root.path());
        let spool = Spool::open_durable(config.clone()).expect("fresh durable bootstrap");
        let expected = ObjectIdentity {
            sha256: Sha256Digest::of(b"authenticated bytes"),
            size: 19,
        };
        let reservation = spool.reserve(expected.size).expect("reservation");
        let mut writer = spool
            .begin_write(reservation, expected)
            .await
            .expect("writer");
        writer
            .write(Bytes::from_static(b"authenticated bytes"))
            .await
            .expect("write");
        let object = writer.commit().await.expect("verified commit");
        let object_path = object.path().to_owned();
        drop(object);
        drop(spool);
        let abandoned = root.path().join("temporary/uncertain.part");
        fs::write(&abandoned, b"uncertain reservation bytes").expect("crash leftover");
        let database = root.path().join("state.sqlite");
        match corruption {
            "empty" => {
                File::create(&database).expect("empty existing database");
            }
            "truncated" => {
                let mut header = [0u8; 128];
                File::open(&database)
                    .expect("database")
                    .read_exact(&mut header)
                    .expect("original prefix");
                let mut file = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&database)
                    .expect("truncate existing database");
                file.write_all(&header).expect("partial header only");
                file.sync_all().expect("persist truncation");
            }
            "missing" => {
                fs::remove_file(&database).expect("lose catalog");
            }
            "version" => {
                Connection::open(&database)
                    .expect("database")
                    .execute_batch("PRAGMA user_version=99;")
                    .expect("incompatible version");
            }
            "schema" => {
                Connection::open(&database)
                    .expect("database")
                    .execute_batch("DROP TABLE reservations;")
                    .expect("incomplete schema");
            }
            _ => unreachable!("enumerated corruption mode"),
        }
        assert!(
            Spool::open_durable(config).is_err(),
            "{corruption} catalog must fail before reconciliation"
        );
        assert_eq!(
            fs::read(&object_path).expect("verified inode preserved"),
            b"authenticated bytes",
            "{corruption}"
        );
        assert_eq!(
            fs::read(&abandoned).expect("uncertain temporary preserved"),
            b"uncertain reservation bytes",
            "{corruption}"
        );
        match corruption {
            "empty" => assert_eq!(
                fs::metadata(&database)
                    .expect("empty catalog retained")
                    .len(),
                0
            ),
            "truncated" => assert_eq!(
                fs::metadata(&database).expect("truncation retained").len(),
                128
            ),
            "missing" => assert!(!database.exists(), "missing authority is not recreated"),
            _ => {}
        }
    }
}
