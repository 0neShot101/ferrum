use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use ferrum_apt::digest::{Sha256Digest, Sha256Hasher, Sha512Digest, Sha512Hasher};
use ferrum_apt::path::RepositoryPath;
use ferrum_apt::release::ReleaseEntry;
use reqwest::{Client, StatusCode, Url};
use serde::Serialize;
use tokio::io::AsyncWriteExt;

use crate::selection::Suite;

pub(crate) const TRANSFER_CAP: u64 = 1024 * 1024 * 1024;
pub(crate) const MANIFEST_CAP: u64 = 32 * 1024 * 1024;
const RESPONSE_ALLOWANCE: u64 = 64 * 1024;

#[derive(Default, Serialize)]
pub(crate) struct Budget {
    pub(crate) body_bytes: u64,
    pub(crate) response_allowance_bytes: u64,
    pub(crate) requests: u64,
}

impl Budget {
    pub(crate) fn charged(&self) -> Result<u64> {
        self.body_bytes
            .checked_add(self.response_allowance_bytes)
            .context("transfer counter overflow")
    }
}

#[derive(Serialize)]
pub(crate) struct Download {
    pub(crate) url: String,
    pub(crate) bytes: u64,
    pub(crate) sha256: String,
    pub(crate) sha512: String,
    pub(crate) canonical_fallback: bool,
}

pub(crate) fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_secs(60))
        .timeout(Duration::from_secs(600))
        .user_agent("Ferrum-B01-distribution-inventory/0.1")
        .build()?)
}

pub(crate) fn source_url(suite: &Suite, path: &str) -> Result<Url> {
    let path = RepositoryPath::parse_decoded(path)?;
    let mut url = Url::parse(suite.root)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|()| anyhow::anyhow!("non-base upstream URL"))?;
        segments.pop_if_empty().push("dists").push(suite.name);
        for segment in path.segments() {
            segments.push(segment);
        }
    }
    ensure!(
        url.scheme() == "https" && url.host_str() == Url::parse(suite.root)?.host_str(),
        "upstream origin changed"
    );
    Ok(url)
}

async fn fetch(
    client: &Client,
    budget: &mut Budget,
    url: Url,
    path: &Path,
    cap: u64,
) -> Result<Option<Download>> {
    let reservation = cap
        .checked_add(RESPONSE_ALLOWANCE)
        .context("transfer reservation overflow")?;
    ensure!(
        budget
            .charged()?
            .checked_add(reservation)
            .is_some_and(|total| total <= TRANSFER_CAP),
        "1 GiB transfer budget cannot admit {} bytes for {url}",
        reservation
    );
    budget.requests = budget
        .requests
        .checked_add(1)
        .context("request count overflow")?;
    budget.response_allowance_bytes = budget
        .response_allowance_bytes
        .checked_add(RESPONSE_ALLOWANCE)
        .context("response allowance overflow")?;
    let mut response = client
        .get(url.clone())
        .header("Accept-Encoding", "identity")
        .send()
        .await?;
    if response.status() == StatusCode::NOT_FOUND || response.status() == StatusCode::GONE {
        return Ok(None);
    }
    ensure!(
        response.status() == StatusCode::OK,
        "{url}: expected HTTP 200, received {} (redirects forbidden)",
        response.status()
    );
    ensure!(
        response
            .headers()
            .get("content-encoding")
            .is_none_or(|value| value == "identity"),
        "HTTP content encoding forbidden: {url}"
    );
    if let Some(length) = response.content_length() {
        ensure!(
            length <= cap,
            "{url}: Content-Length {length} exceeds {cap}"
        );
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .await?;
    let mut bytes = 0_u64;
    let mut sha256 = Sha256Hasher::new();
    let mut sha512 = Sha512Hasher::new();
    while let Some(chunk) = response.chunk().await? {
        let length = u64::try_from(chunk.len())?;
        budget.body_bytes = budget
            .body_bytes
            .checked_add(length)
            .context("body counter overflow")?;
        bytes = bytes
            .checked_add(length)
            .context("download size overflow")?;
        ensure!(bytes <= cap, "{url}: body exceeds {cap} bytes");
        ensure!(
            budget.charged()? <= TRANSFER_CAP,
            "1 GiB transfer budget exceeded"
        );
        sha256.update(&chunk);
        sha512.update(&chunk);
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    Ok(Some(Download {
        url: url.to_string(),
        bytes,
        sha256: sha256.finalize().to_hex(),
        sha512: sha512.finalize().to_hex(),
        canonical_fallback: false,
    }))
}

pub(crate) async fn inrelease(
    client: &Client,
    budget: &mut Budget,
    suite: &Suite,
    path: &Path,
) -> Result<Download> {
    fetch(
        client,
        budget,
        source_url(suite, "InRelease")?,
        path,
        MANIFEST_CAP,
    )
    .await?
    .context("required InRelease unavailable")
}

pub(crate) async fn packages(
    client: &Client,
    budget: &mut Budget,
    suite: &Suite,
    entry: &ReleaseEntry,
    path: &Path,
) -> Result<Download> {
    let (parent, _) = entry.path.split_last();
    let (algorithm, digest) = if let Some(digest) = entry.sha256 {
        ("SHA256", digest.to_hex())
    } else {
        (
            "SHA512",
            entry
                .sha512
                .context("selected entry has no SHA-2 digest")?
                .to_hex(),
        )
    };
    let by_hash = match parent {
        Some(parent) => format!("{parent}/by-hash/{algorithm}/{digest}"),
        None => format!("by-hash/{algorithm}/{digest}"),
    };
    let download = fetch(
        client,
        budget,
        source_url(suite, &by_hash)?,
        path,
        entry.size,
    )
    .await?;
    let download = match download {
        Some(download) => download,
        None => {
            let mut download = fetch(
                client,
                budget,
                source_url(suite, entry.path.as_str())?,
                path,
                entry.size,
            )
            .await?
            .context("both by-hash and canonical Packages unavailable")?;
            download.canonical_fallback = true;
            download
        }
    };
    verify(entry, download.bytes, &download.sha256, &download.sha512)?;
    Ok(download)
}

pub(crate) fn verify(entry: &ReleaseEntry, size: u64, sha256: &str, sha512: &str) -> Result<()> {
    ensure!(
        size == entry.size,
        "{}: signed size {} != actual {size}",
        entry.path,
        entry.size
    );
    if let Some(expected) = entry.sha256 {
        ensure!(
            Sha256Digest::from_hex(sha256)? == expected,
            "{}: SHA256 mismatch",
            entry.path
        );
    }
    if let Some(expected) = entry.sha512 {
        ensure!(
            Sha512Digest::from_hex(sha512)? == expected,
            "{}: SHA512 mismatch",
            entry.path
        );
    }
    ensure!(
        entry.sha256.is_some() || entry.sha512.is_some(),
        "entry lacks SHA-2 digest"
    );
    Ok(())
}
