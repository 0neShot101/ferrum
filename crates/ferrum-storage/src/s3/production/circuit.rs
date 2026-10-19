use super::*;
pub(super) struct CircuitPermit {
    circuit: Arc<Mutex<Circuit>>,
    owns_probe: bool,
    response: bool,
    finished: bool,
}
impl CircuitPermit {
    pub(super) fn acquire(circuit: Arc<Mutex<Circuit>>) -> Result<Self, S3Error> {
        let owns_probe = {
            let mut state = circuit.lock().map_err(|_| S3Error::Unavailable)?;
            if state.forbidden {
                return Err(S3Error::Forbidden);
            }
            if let Some(until) = state.until {
                if Instant::now() < until || state.probe {
                    return Err(S3Error::Unavailable);
                }
                state.probe = true;
                true
            } else {
                false
            }
        };
        Ok(Self {
            circuit,
            owns_probe,
            response: false,
            finished: false,
        })
    }
    pub(super) fn body_started(&mut self) {
        self.response = true;
    }
    pub(super) fn finish_body(&mut self, error: Option<&S3Error>) {
        if self.response {
            self.finish(error);
        }
    }
    pub(super) fn finish(&mut self, error: Option<&S3Error>) {
        if self.finished {
            return;
        }
        self.finished = true;
        if let Ok(mut state) = self.circuit.lock() {
            match error {
                Some(S3Error::Forbidden) => state.forbidden = true,
                Some(S3Error::Timeout | S3Error::Unavailable | S3Error::Throttled) => {
                    state.transient = state.transient.saturating_add(1);
                    if state.transient >= 5 {
                        state.until = Some(Instant::now() + Duration::from_secs(30));
                    }
                }
                None | Some(S3Error::NotFound | S3Error::Conflict) => {
                    state.transient = 0;
                    state.until = None;
                }
                _ => {}
            }
        }
    }
}
impl Drop for CircuitPermit {
    fn drop(&mut self) {
        // Header failures are classified by the SDK caller. Successful GET
        // headers are not success: a dropped/truncated body is one failure.
        if self.response && !self.finished {
            self.finish(Some(&S3Error::Unavailable));
        }
        if self.owns_probe
            && let Ok(mut state) = self.circuit.lock()
        {
            state.probe = false;
        }
    }
}
