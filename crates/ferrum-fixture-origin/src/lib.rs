//! Fault-injectable loopback HTTP origin for Ferrum verification fixtures.
//!
//! Test tooling only: both listeners refuse non-loopback addresses. The data listener
//! serves files under a root at a fixed prefix; the control listener mutates faults,
//! settings and the served root and exposes the request log.

pub mod control;
pub mod faults;
pub mod server;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::Context as _;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub use faults::{Fault, FaultKind, LogEntry};
pub use server::{Origin, bind_loopback, require_loopback};

/// Startup parameters shared by the binary and embedded test use.
#[derive(Clone, Debug)]
pub struct OriginConfig {
    pub root: PathBuf,
    pub listen: SocketAddr,
    pub control: SocketAddr,
    pub prefix: String,
}

/// Both servers running on background tasks until [`RunningOrigin::shutdown`].
pub struct RunningOrigin {
    origin: Origin,
    data_addr: SocketAddr,
    control_addr: SocketAddr,
    data_stop: oneshot::Sender<()>,
    control_stop: oneshot::Sender<()>,
    data_task: JoinHandle<std::io::Result<()>>,
    control_task: JoinHandle<std::io::Result<()>>,
}

impl RunningOrigin {
    /// Bind both listeners (port `0` picks an ephemeral port) and start serving.
    ///
    /// # Errors
    /// Non-loopback addresses, bind failures, a missing root directory or an invalid
    /// prefix.
    pub async fn bind(config: OriginConfig) -> anyhow::Result<RunningOrigin> {
        let origin = Origin::new(config.root, config.prefix)
            .await
            .context("invalid origin configuration")?;
        let data_listener = bind_loopback(config.listen)
            .await
            .context("data listener")?;
        let control_listener = bind_loopback(config.control)
            .await
            .context("control listener")?;
        let data_addr = data_listener
            .local_addr()
            .context("data listener address")?;
        let control_addr = control_listener
            .local_addr()
            .context("control listener address")?;

        let (data_stop, data_stopped) = oneshot::channel();
        let (control_stop, control_stopped) = oneshot::channel();
        let data_task = tokio::spawn(
            axum::serve(data_listener, origin.data_router())
                .with_graceful_shutdown(async {
                    let _ = data_stopped.await;
                })
                .into_future(),
        );
        let control_task = tokio::spawn(
            axum::serve(control_listener, origin.control_router())
                .with_graceful_shutdown(async {
                    let _ = control_stopped.await;
                })
                .into_future(),
        );
        tracing::info!(%data_addr, %control_addr, root = %origin.root().display(), prefix = origin.prefix(), "fixture origin listening");
        Ok(RunningOrigin {
            origin,
            data_addr,
            control_addr,
            data_stop,
            control_stop,
            data_task,
            control_task,
        })
    }

    pub fn data_addr(&self) -> SocketAddr {
        self.data_addr
    }

    pub fn control_addr(&self) -> SocketAddr {
        self.control_addr
    }

    /// Shared state behind both servers, for in-process inspection.
    pub fn origin(&self) -> &Origin {
        &self.origin
    }

    /// Stop accepting, let in-flight requests finish, and wait for both servers.
    pub async fn shutdown(self) {
        let _ = self.data_stop.send(());
        let _ = self.control_stop.send(());
        for (name, task) in [("data", self.data_task), ("control", self.control_task)] {
            match task.await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::warn!(server = name, %error, "server exited with error"),
                Err(error) => tracing::warn!(server = name, %error, "server task failed"),
            }
        }
    }
}
