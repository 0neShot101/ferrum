//! One owned, bounded filesystem pool. Cancellation drops only the reply:
//! admitted closures keep their inode, pin and byte charge until completion.

use std::io;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use tokio::sync::{OwnedSemaphorePermit, oneshot};

use super::{SpoolError, lock_unpoisoned};

type Job = Box<dyn FnOnce() + Send + 'static>;

pub(crate) struct IoPool {
    sender: mpsc::SyncSender<Job>,
}

impl IoPool {
    pub(crate) fn new(workers: usize) -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Job>(workers);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..workers {
            let receiver = Arc::clone(&receiver);
            thread::Builder::new()
                .name(format!("ferrum-filesystem-{index}"))
                .spawn(move || {
                    loop {
                        let next = lock_unpoisoned(&receiver).recv();
                        match next {
                            Ok(job) => job(),
                            Err(_) => break,
                        }
                    }
                })?;
        }
        Ok(Self { sender })
    }

    // Callers hold a shared I/O permit before enqueueing, limiting queued plus
    // active jobs to the worker count. No unbounded blocking-pool submission.
    pub(crate) async fn run<T: Send + 'static>(
        &self,
        permit: OwnedSemaphorePermit,
        operation: impl FnOnce() -> T + Send + 'static,
    ) -> Result<T, SpoolError> {
        let (reply, result) = oneshot::channel();
        let job: Job = Box::new(move || {
            let _permit = permit;
            let _ = reply.send(operation());
        });
        self.sender
            .try_send(job)
            .map_err(|_| io::Error::other("filesystem worker pool unavailable"))?;
        result
            .await
            .map_err(|_| SpoolError::Io(io::Error::other("filesystem worker stopped")))
    }
}
