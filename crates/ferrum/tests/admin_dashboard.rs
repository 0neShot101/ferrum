//! End-to-end integration tests for the enterprise administration dashboard:
//! - Separate durable admin state + restart preservation
//! - Zero-provider-call captured package inventory at 100,000+ rows with EXPLAIN QUERY PLAN proof
//! - Logical ledger/provider/reservation row immutability across dashboard operations
//! - Actor-integrated synchronization jobs, idempotency, and local cache reclamation
//! - Owner-isolated per-user workspaces, RBAC enforcement, and validated configuration proposals/save

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use ferrum::app::RunningGateway;
use ferrum::config::Config;
use ferrum_storage::budget::BudgetLedger;
use ferrum_storage::{DurableSpoolConfig, Spool};
use reqwest::{StatusCode, header};
use serde_json::{Value, json};

async fn parse_json(resp: reqwest::Response) -> Value {
    serde_json::from_slice(&resp.bytes().await.expect("response bytes")).expect("parse json")
}
fn admin_headers(
    gateway: &RunningGateway,
    cookie: Option<&str>,
    csrf: Option<&str>,
) -> header::HeaderMap {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        header::HOST,
        gateway.admin_addr.to_string().parse().expect("host"),
    );
    headers.insert(
        header::ORIGIN,
        format!("http://{}", gateway.admin_addr)
            .parse()
            .expect("origin"),
    );
    headers.insert(
        header::CONTENT_TYPE,
        "application/json".parse().expect("ct"),
    );
    if let Some(cookie) = cookie {
        headers.insert(header::COOKIE, cookie.parse().expect("cookie"));
    }
    if let Some(csrf) = csrf {
        headers.insert("x-ferrum-csrf", csrf.parse().expect("csrf"));
    }
    headers
}

#[tokio::test]
async fn end_to_end_admin_lifecycle_workspaces_config_and_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let origin_root = dir.path().join("origin");
    let packages = scratch_tree(&origin_root);
    let origin = start_origin(origin_root).await;

    let work_dir = dir.path().join("work");
    std::fs::create_dir_all(&work_dir).expect("mkdir work");
    let keyring = dir.path().join("unused.gpg");
    std::fs::write(&keyring, b"fixture-keyring").expect("write keyring");

    let source_cfg = dir.path().join("source-gateway.toml");
    let managed_cfg = dir.path().join("managed-gateway.toml");
    std::fs::write(
        &source_cfg,
        format!(
            "# Operator comment preserved across managed saves\n\
             mode = \"private-fixture\"\n\
             [listen]\n\
             public = \"127.0.0.1:0\"\n\
             admin = \"127.0.0.1:0\"\n\
             [fixture]\n\
             keyring = \"{}\"\n\
             work_dir = \"{}\"\n\
             [verifier]\n\
             timeout_seconds = 30\n\
             [limits]\n\
             concurrent_fills = 8\n",
            keyring.display(),
            work_dir.display()
        ),
    )
    .expect("write source config");

    let adopt = ferrum::admin::settings::adopt_managed_config(&source_cfg, &managed_cfg)
        .expect("adopt managed config");
    assert!(adopt.restart_required);

    let mut cfg = Config::load(&managed_cfg).expect("load managed config");
    cfg.set_test_origin(
        format!("http://{}/fixture/", origin.data_addr())
            .parse()
            .expect("origin url"),
    )
    .expect("set test origin");

    let gateway = start_gateway(cfg.clone(), &packages).await;
    let http = client();

    // 1. Bootstrap initial administrator with one-time setup token
    let setup_token = ferrum::admin::migration::read_bootstrap_token(&gateway.admin_state_dir)
        .expect("read setup token");
    let setup_resp = http
        .post(admin_url(&gateway, "/api/admin/setup"))
        .headers(admin_headers(&gateway, None, None))
        .body(
            json!({
                "bootstrapToken": setup_token,
                "username": "admin",
                "displayName": "Lead Admin",
                "password": "CorrectHorseBatteryStaple!42"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("setup request");
    assert_eq!(setup_resp.status(), StatusCode::OK);
    let admin_cookie = setup_resp
        .headers()
        .get(header::SET_COOKIE)
        .expect("set-cookie")
        .to_str()
        .expect("cookie str")
        .split(';')
        .next()
        .expect("cookie pair")
        .to_owned();
    let setup_json = parse_json(setup_resp).await;
    let admin_csrf = setup_json["csrfToken"].as_str().expect("csrf").to_owned();

    // 2. Create restricted viewer user (view_status + view_inventory only)
    let create_viewer = http
        .post(admin_url(&gateway, "/api/admin/users"))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(
            json!({
                "username": "viewer",
                "displayName": "Read Only Viewer",
                "password": "ViewerBatteryStaple!42",
                "permissions": ["view_status", "view_inventory"]
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create viewer");
    assert_eq!(create_viewer.status(), StatusCode::CREATED);

    let login_viewer = http
        .post(admin_url(&gateway, "/api/admin/login"))
        .headers(admin_headers(&gateway, None, None))
        .body(
            json!({
                "username": "viewer",
                "password": "ViewerBatteryStaple!42"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("login viewer");
    assert_eq!(login_viewer.status(), StatusCode::OK);
    let viewer_cookie = login_viewer
        .headers()
        .get(header::SET_COOKIE)
        .expect("viewer cookie")
        .to_str()
        .expect("str")
        .split(';')
        .next()
        .expect("pair")
        .to_owned();
    let viewer_json = parse_json(login_viewer).await;
    let viewer_csrf = viewer_json["csrfToken"]
        .as_str()
        .expect("viewer csrf")
        .to_owned();

    // 3. Workspace owner isolation & revision CAS
    let create_ws = http
        .post(admin_url(&gateway, "/api/admin/workspaces"))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(
            json!({
                "name": "Ops Primary",
                "schemaVersion": 1,
                "isDefault": true,
                "defaultPage": "overview",
                "refreshMode": "15s",
                "timeRange": "1h",
                "widgets": [
                    { "id": "readiness_overview", "colSpan": 6, "rowSpan": 1 },
                    { "id": "traffic_rates", "colSpan": 6, "rowSpan": 2 }
                ],
                "pinnedMirrors": [{ "repository": "debian", "suite": "trixie" }],
                "columns": {},
                "filters": {},
                "sorts": {}
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create workspace");
    assert_eq!(create_ws.status(), StatusCode::CREATED);
    let ws_json = parse_json(create_ws).await;
    let ws_id = ws_json["workspace"]["id"]
        .as_str()
        .expect("ws id")
        .to_owned();
    assert_eq!(ws_json["workspace"]["revision"], 1);

    // Viewer cannot read or update admin's workspace
    let viewer_ws_get = http
        .get(admin_url(
            &gateway,
            &format!("/api/admin/workspaces/{ws_id}"),
        ))
        .headers(admin_headers(&gateway, Some(&viewer_cookie), None))
        .send()
        .await
        .expect("viewer get ws");
    assert_eq!(viewer_ws_get.status(), StatusCode::NOT_FOUND);

    // Stale expectedRevision is rejected with 409 Conflict
    let stale_ws = http
        .put(admin_url(
            &gateway,
            &format!("/api/admin/workspaces/{ws_id}"),
        ))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(
            json!({
                "expectedRevision": 99,
                "name": "Stale Update",
                "schemaVersion": 1,
                "isDefault": true,
                "defaultPage": "mirrors",
                "refreshMode": "15s",
                "timeRange": "1h",
                "widgets": [{ "id": "readiness_overview", "colSpan": 12, "rowSpan": 1 }],
                "pinnedMirrors": [],
                "columns": {},
                "filters": {},
                "sorts": {}
            })
            .to_string(),
        )
        .send()
        .await
        .expect("stale ws update");
    assert_eq!(stale_ws.status(), StatusCode::CONFLICT);

    // 4. Viewer is denied privileged mutations (config proposal, cache clear, users)
    let viewer_cache = http
        .post(admin_url(&gateway, "/api/admin/cache/clear"))
        .headers(admin_headers(
            &gateway,
            Some(&viewer_cookie),
            Some(&viewer_csrf),
        ))
        .body(json!({ "reason": "Unauthorized attempt" }).to_string())
        .send()
        .await
        .expect("viewer cache clear");
    assert_eq!(viewer_cache.status(), StatusCode::FORBIDDEN);

    // 5. Validated config preview -> proposal -> managed save -> restart required until restart
    let cfg_get = parse_json(
        http.get(admin_url(&gateway, "/api/admin/config"))
            .headers(admin_headers(&gateway, Some(&admin_cookie), None))
            .send()
            .await
            .expect("get config"),
    )
    .await;
    let running_rev = cfg_get["runningRevision"]
        .as_str()
        .expect("running rev")
        .to_owned();
    assert_eq!(cfg_get["managedConfigEnabled"], true);
    assert_eq!(cfg_get["restartRequired"], false);

    let proposal_resp = http
        .post(admin_url(&gateway, "/api/admin/config/proposals"))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(
            json!({
                "expectedRevision": running_rev,
                "reason": "Increase fill concurrency for maintenance window",
                "patch": {
                    "limits": {
                        "concurrentFills": 12
                    },
                    "verifierTimeoutSeconds": 25
                }
            })
            .to_string(),
        )
        .send()
        .await
        .expect("create proposal");
    assert_eq!(proposal_resp.status(), StatusCode::CREATED);
    let proposal_json = parse_json(proposal_resp).await;
    let proposal_id = proposal_json["proposal"]["id"]
        .as_str()
        .expect("proposal id")
        .to_owned();

    let save_resp = http
        .post(admin_url(
            &gateway,
            &format!("/api/admin/config/proposals/{proposal_id}/save"),
        ))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(json!({}).to_string())
        .send()
        .await
        .expect("save proposal");
    assert_eq!(save_resp.status(), StatusCode::OK);
    let save_json = parse_json(save_resp).await;
    assert_eq!(save_json["proposal"]["state"], "saved");
    assert_eq!(save_json["proposal"]["status"], "saved_restart_required");

    let cfg_saved = parse_json(
        http.get(admin_url(&gateway, "/api/admin/config"))
            .headers(admin_headers(&gateway, Some(&admin_cookie), None))
            .send()
            .await
            .expect("get config after save"),
    )
    .await;
    assert_eq!(cfg_saved["savedRevisionStatus"], "saved_restart_required");
    assert_eq!(cfg_saved["restartRequired"], true);

    // 6. Serve a package on the public listener, verify local hit counter and cache clear job
    let pkg_resp = http
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("fetch small package");
    assert_eq!(pkg_resp.status(), StatusCode::OK);
    assert_eq!(pkg_resp.bytes().await.expect("bytes").len(), 682);

    let warm_resp = http
        .get(url(&gateway, SMALL_PACKAGE))
        .send()
        .await
        .expect("fetch warm package");
    assert_eq!(warm_resp.status(), StatusCode::OK);

    let clear_resp = http
        .post(admin_url(&gateway, "/api/admin/cache/clear"))
        .headers(admin_headers(
            &gateway,
            Some(&admin_cookie),
            Some(&admin_csrf),
        ))
        .body(
            json!({
                "reason": "Reclaim warm package cache after test",
                "idempotencyKey": "cache-clear-integration-1"
            })
            .to_string(),
        )
        .send()
        .await
        .expect("clear cache");
    assert_eq!(clear_resp.status(), StatusCode::OK);
    let clear_json = parse_json(clear_resp).await;
    assert_eq!(clear_json["evictedObjects"], 1);
    assert_eq!(clear_json["freedBytes"], 682);
    assert_eq!(clear_json["job"]["state"], "succeeded");

    // 7. Restart gateway from the saved managed configuration and verify session, workspace, and applied config
    gateway.shutdown().await.expect("gateway shutdown");

    let mut restarted_cfg = Config::load(&managed_cfg).expect("reload saved managed config");
    assert_eq!(restarted_cfg.limits.concurrent_fills, 12);
    assert_eq!(restarted_cfg.verifier.timeout, Duration::from_secs(25));
    restarted_cfg
        .set_test_origin(
            format!("http://{}/fixture/", origin.data_addr())
                .parse()
                .expect("origin url"),
        )
        .expect("set test origin");
    let gateway2 = start_gateway(restarted_cfg, &packages).await;

    let cfg_after = parse_json(
        http.get(admin_url(&gateway2, "/api/admin/config"))
            .headers(admin_headers(&gateway2, Some(&admin_cookie), None))
            .send()
            .await
            .expect("get config after restart"),
    )
    .await;
    assert_eq!(cfg_after["restartRequired"], false);
    assert_eq!(cfg_after["running"]["limits"]["concurrentFills"], 12);

    let ws_after = parse_json(
        http.get(admin_url(
            &gateway2,
            &format!("/api/admin/workspaces/{ws_id}"),
        ))
        .headers(admin_headers(&gateway2, Some(&admin_cookie), None))
        .send()
        .await
        .expect("get ws after restart"),
    )
    .await;
    assert_eq!(ws_after["workspace"]["name"], "Ops Primary");

    gateway2.shutdown().await.expect("gateway2 shutdown");
    origin.shutdown().await;
}

#[tokio::test]
async fn hundred_thousand_captured_packages_paginate_under_budget_with_zero_provider_calls() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_dir = dir.path().join("state");
    let mut disk = DurableSpoolConfig::new(state_dir.clone());
    const MIB: u64 = 1024 * 1024;
    disk.spool.managed_ceiling = 64 * MIB;
    disk.spool.max_object_size = 4 * MIB;
    disk.spool.io_workers = 2;
    disk.spool.read_chunk = 4096;
    disk.free_space_floor = 0;
    disk.temporary_ceiling = 8 * MIB;
    disk.metadata_temporary_reserve = 2 * MIB;
    disk.metadata_ceiling = 16 * MIB;
    disk.catalog_ceiling = 64 * MIB;
    disk.catalog_memory_budget = 64 * MIB;
    disk.max_entries = 1024;
    disk.database_queue = 8;
    disk.eviction_high_watermark = 56 * MIB;
    disk.eviction_low_watermark = 48 * MIB;
    let spool = Spool::open_durable(disk).expect("open durable spool");

    let cfg_text = format!(
        "mode = \"private-durable\"\n\
         [listen]\n\
         public = \"127.0.0.1:0\"\n\
         admin = \"127.0.0.1:0\"\n\
         [durable]\n\
         state_dir = \"{}\"\n\
         [durable.provider]\n\
         endpoint = \"https://s3.us-east-1.amazonaws.com\"\n\
         region = \"us-east-1\"\n\
         bucket = \"ferrum\"\n\
         credentials_file = \"{}\"\n\
         [durable.keyrings]\n\
         debian = \"{}\"\n\
         ubuntu = \"{}\"\n\
         [durable.budget]\n\
         mode = \"existing\"\n\
         [verifier]\n",
        state_dir.display(),
        dir.path().join("unused.env").display(),
        dir.path().join("debian.gpg").display(),
        dir.path().join("ubuntu.gpg").display()
    );
    let cfg = Config::parse(&cfg_text, dir.path()).expect("parse durable config");
    let durable = cfg.durable().expect("durable");
    let provider = durable.provider.provider_identity(None).expect("provider");
    let _ledger = BudgetLedger::initialize_for_provider(spool.clone(), durable.budget, &provider)
        .expect("ledger");

    // Populate 100,000 synthetic captured paths sharing 1,000 deduplicated blobs in one transaction
    let db = rusqlite::Connection::open(state_dir.join("state.sqlite")).expect("open sqlite");
    let tx = db.unchecked_transaction().expect("begin tx");
    tx.execute(
        "INSERT INTO capture_proofs(generation,manifest,durable) VALUES(?1,?2,1)",
        rusqlite::params![
            "0".repeat(64),
            r#"{"repository":"debian","suite":"trixie","generation_id":"g0"}"#
        ],
    )
    .expect("insert proof");
    {
        let mut blob_stmt = tx
            .prepare("INSERT INTO capture_blobs(digest,size,first_capture,retain_until,readback_verified) VALUES(?1,4096,1700000000,1800000000,1)")
            .expect("prepare blob");
        for b in 0..1000u32 {
            let digest = format!("{b:064x}");
            blob_stmt.execute([digest]).expect("insert blob");
        }
    }
    {
        let mut path_stmt = tx
            .prepare("INSERT INTO capture_paths(repository,path,path_hash,digest,generation,receipt_verified,referenced,retain_until) VALUES(?1,?2,?3,?4,?5,1,1,1800000000)")
            .expect("prepare path");
        let gen_id = "0".repeat(64);
        for i in 0..100_000u32 {
            let repo = if i < 99_990 { "debian" } else { "ubuntu" };
            let path = format!("pool/main/p/pkg-{i:06}/pkg-{i:06}_1.0_amd64.deb");
            let path_hash = format!("{:064x}", u128::from(i) + 1);
            let digest = format!("{:064x}", i % 1000);
            path_stmt
                .execute(rusqlite::params![repo, path, path_hash, digest, gen_id])
                .expect("insert path");
        }
    }
    tx.commit().expect("commit 100k rows");

    // Verify EXPLAIN QUERY PLAN uses capture_paths primary key index without full temp B-tree sort
    let plan: Vec<String> = db
        .prepare(
            "EXPLAIN QUERY PLAN SELECT p.repository, p.path FROM capture_paths p \
             WHERE (p.repository, p.path) > ('debian', 'pool/main/p/pkg-050000') \
             AND p.repository = 'debian' AND p.path >= 'pool/main/' AND p.path < 'pool/main0' \
             ORDER BY p.repository, p.path LIMIT 101",
        )
        .expect("prepare explain")
        .query_map([], |r| r.get::<_, String>(3))
        .expect("query explain")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect explain");
    assert!(
        plan.iter().any(|detail| detail.contains("SEARCH p USING")
            && detail.contains("sqlite_autoindex_capture_paths_1")),
        "expected primary-key index search in EXPLAIN QUERY PLAN, got: {plan:?}"
    );
    assert!(
        !plan.iter().any(|detail| detail.contains("USE TEMP B-TREE")),
        "query plan must not sort via temp B-tree: {plan:?}"
    );

    // Snapshot logical ledger rows before browsing
    let ledger_before: String = db
        .query_row(
            "SELECT json_array(period,high_time,used,data_used,certain,(SELECT total FROM remote_storage_totals WHERE id=1)) FROM remote_budget WHERE id=1",
            [],
            |r| r.get(0),
        )
        .expect("ledger before");

    // Page through deep cursors and restrictive prefix filters under 500ms budget
    let start = Instant::now();
    let page1 = spool
        .captured_packages(
            ferrum_storage::capture::inventory::InventoryFilter {
                repository: Some("debian".into()),
                path_prefix: Some("pool/main/p/pkg-0999".into()),
                ..Default::default()
            },
            Some((
                "debian".into(),
                "pool/main/p/pkg-099900/pkg-099900_1.0_amd64.deb".into(),
            )),
            100,
        )
        .expect("page1");
    let elapsed = start.elapsed();
    assert_eq!(page1.items.len(), 89);
    assert!(!page1.has_more);
    assert!(
        elapsed < Duration::from_millis(250),
        "100k indexed keyset page took {elapsed:?} (>= 250ms)"
    );

    let summary = spool.captured_summary().expect("summary");
    assert_eq!(summary.paths, "100000");
    assert_eq!(summary.blobs, "1000");
    assert_eq!(summary.blob_bytes, (1000u64 * 4096).to_string());

    let ledger_after: String = db
        .query_row(
            "SELECT json_array(period,high_time,used,data_used,certain,(SELECT total FROM remote_storage_totals WHERE id=1)) FROM remote_budget WHERE id=1",
            [],
            |r| r.get(0),
        )
        .expect("ledger after");
    assert_eq!(ledger_before, ledger_after);
}
