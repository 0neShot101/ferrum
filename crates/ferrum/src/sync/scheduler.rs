//! Fixed, security-first suite rounds. Arrival never rewinds a running round.

use ferrum_storage::checkpoint::SuiteKey;

/// The production identity set is finite; fixture mode uses its single slot.
pub const MAX_SUITES: usize = ferrum_storage::checkpoint::MAX_SUITES;

/// Incremental dispatcher shared by the live scheduler and qualification harness.
/// Each suite receives at most one opportunity per round, including refused
/// admission. Eligibility changes cannot move a security suite ahead twice.
pub struct FairRounds {
    order: [usize; MAX_SUITES],
    count: usize,
    cursor: usize,
    round: u64,
}

impl FairRounds {
    pub fn new(keys: &[SuiteKey]) -> Result<Self, super::SyncError> {
        if keys.is_empty() || keys.len() > MAX_SUITES {
            return Err(super::SyncError::Identity(
                "invalid configured suite count".into(),
            ));
        }
        let mut order = [0; MAX_SUITES];
        let mut count = 0;
        for security in [true, false] {
            for (index, key) in keys.iter().enumerate() {
                if key.suite().ends_with("-security") == security {
                    order[count] = index;
                    count += 1;
                }
            }
        }
        Ok(Self {
            order,
            count,
            cursor: 0,
            round: 0,
        })
    }

    /// Advances one opportunity, whether or not its caller can admit work.
    /// Callers must not retry a refused object before yielding this opportunity.
    pub fn next_opportunity(&mut self) -> (u64, usize) {
        if self.cursor == self.count {
            self.cursor = 0;
            self.round = self.round.saturating_add(1);
        }
        let index = self.order[self.cursor];
        self.cursor += 1;
        (self.round, index)
    }

    pub fn suite_count(&self) -> usize {
        self.count
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn security_arrival_never_restarts_or_starves_a_round() {
        let keys = [
            ("debian", "trixie"),
            ("debian", "trixie-updates"),
            ("debian-security", "trixie-security"),
            ("ubuntu", "noble"),
            ("ubuntu", "noble-updates"),
            ("ubuntu-security", "noble-security"),
        ]
        .map(|(repository, suite)| SuiteKey::new(repository, suite).expect("fixed key"));
        let mut rounds = FairRounds::new(&keys).expect("six suites");
        for round in 0..100 {
            let opportunities: Vec<_> = (0..6).map(|_| rounds.next_opportunity()).collect();
            assert_eq!(
                opportunities,
                [2, 5, 0, 1, 3, 4].map(|index| (round, index))
            );
        }
    }
}
