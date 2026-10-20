use super::*;

/// Prepared exclusively from authenticated, configured catalog membership.
/// Byte/object charges include a possible detached signature, not just payload.
pub(crate) struct PreparedWarm {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) objects: usize,
    request: PackageRequest,
    _package: PackageDescriptor,
}

pub(crate) async fn prepare_warm(
    state: &Arc<AppState>,
    path: &str,
) -> Result<PreparedWarm, String> {
    if state.catalog.is_fixture() || state.capture.is_none() || state.s3.is_none() {
        return Err("Prewarming requires authenticated durable storage".into());
    }

    let path = RepositoryPath::parse_decoded(path.strip_prefix('/').unwrap_or(path))
        .map_err(|_| "Invalid package path".to_owned())?;
    let authorized = state
        .catalog
        .resolve(&path, &state.prefix)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "Unknown or retired package path".to_owned())?;
    let (
        Resolution::Package {
            identity,
            path: relative,
        },
        Some(package),
    ) = (authorized.resolution, authorized.package)
    else {
        return Err("Path is not an authenticated package".into());
    };
    if relative.as_str().ends_with(".sig") {
        return Err("Specify the package path, not its detached signature".into());
    }

    let client = state
        .clients
        .iter()
        .find(|(repository, _)| repository == authorized.repository)
        .map(|(_, client)| Arc::clone(client))
        .ok_or_else(|| "Package repository is not active".to_owned())?;
    let proof = Arc::new(
        package
            .authorize()
            .await
            .map_err(|error| error.to_string())?,
    );
    let signature = proof.requires_package_signature();
    let size = identity
        .size
        .checked_add(if signature {
            ferrum_apt::pacman::MAX_PACMAN_SIG_BYTES as u64
        } else {
            0
        })
        .ok_or_else(|| "Package byte charge overflow".to_owned())?;

    Ok(PreparedWarm {
        path: path.as_str().to_owned(),
        size,
        objects: if signature { 2 } else { 1 },
        request: PackageRequest {
            identity,
            path: relative,
            client,
            proof: Some(proof),
            deadline: tokio::time::Instant::now() + state.limits.waiter_timeout,
        },
        _package: package,
    })
}

pub(crate) async fn warm_package(
    state: &Arc<AppState>,
    prepared: &PreparedWarm,
    deadline: tokio::time::Instant,
    cancel: CancellationToken,
) -> Result<bool, String> {
    // Recheck active membership at dispatch: queued work must not resurrect a
    // retired path or spend a budget calculated for a different package.
    let mut current = prepare_warm(state, &prepared.path).await?;
    if current.request.identity != prepared.request.identity
        || current.size != prepared.size
        || current.objects != prepared.objects
    {
        return Err("Package authority changed after prewarm admission".into());
    }
    current.request.deadline = deadline;
    let request = &current.request;
    let hit = state.spool.lookup(request.identity).is_some();
    let capture = state.capture.as_ref().ok_or("Capture unavailable")?;
    let proof = request.proof.as_ref().ok_or("Package proof unavailable")?;
    let operation = async {
        loop {
            let joined = state
                .registry
                .join_background(
                    request.identity,
                    &request.path,
                    Arc::clone(&request.client),
                    Arc::clone(capture),
                    Arc::clone(proof),
                    (deadline, cancel.clone()),
                )
                .await;
            match joined {
                Some(JoinOutcome::Verified(_)) => {
                    retain_package_reference(state, request)
                        .await
                        .map_err(|error| error.to_string())?;
                    return Ok(hit);
                }
                Some(JoinOutcome::Failed(error)) => return Err(error.to_string()),
                Some(JoinOutcome::Timeout) => return Err("Prewarm deadline expired".into()),
                Some(JoinOutcome::TooManyWaiters) => {
                    return Err("Package waiter capacity exhausted".into());
                }
                None => {
                    // Retry only admission, never a failed transfer. Background
                    // work yields without joining the foreground semaphore queue.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let refreshed = prepare_warm(state, &prepared.path).await?;
                    if refreshed.request.identity != request.identity {
                        return Err("Package authority changed while prewarm paused".into());
                    }
                }
            }
        }
    };

    tokio::select! {
        biased;
        () = cancel.cancelled() => Err("Prewarm cancelled; shared foreground fills may continue".into()),
        result = tokio::time::timeout_at(deadline, operation) => {
            result.map_err(|_| "Prewarm deadline expired".to_owned())?
        }
    }
}
