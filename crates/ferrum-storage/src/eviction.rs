//! Transient ranking only. The disk owner alone checks eligibility and changes residency.
//! A scan is pulled one candidate at a time: stopping never creates synthetic demand hits.

use ferrum_apt::digest::ObjectIdentity;
use std::collections::HashMap;

pub(crate) const MAX_CANDIDATES: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(
    any(test, feature = "test-harness"),
    derive(serde::Serialize, serde::Deserialize)
)]
#[cfg_attr(any(test, feature = "test-harness"), serde(rename_all = "snake_case"))]
pub enum PolicyKind {
    #[default]
    Clock,
    #[cfg(any(test, feature = "test-harness"))]
    Fifo,
    #[cfg(any(test, feature = "test-harness"))]
    Lru,
    #[cfg(any(test, feature = "test-harness"))]
    SegmentedClock,
}

#[cfg(any(test, feature = "test-harness"))]
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct PolicyStats {
    pub demand_hits: u64,
    pub candidate_inspections: u64,
    pub candidate_proposals: u64,
    pub skipped_notifications: u64,
    pub removals: u64,
    /// Capacity-based payload estimate, NOT allocator-resident bytes or RSS.
    pub memory_estimate_bytes: usize,
    pub resident_entries: usize,
}

#[derive(Default)]
struct List {
    first: Option<usize>,
    last: Option<usize>,
    hand: Option<usize>,
    bytes: u64,
}

struct Entry {
    identity: ObjectIdentity,
    previous: Option<usize>,
    next: Option<usize>,
    protected: bool,
    referenced: bool,
    proposed: u64,
}

pub(crate) struct Policy {
    kind: PolicyKind,
    entries: Vec<Entry>,
    positions: HashMap<ObjectIdentity, usize>,
    free: Option<usize>,
    lists: [List; 2],
    epoch: u64,
    #[cfg(any(test, feature = "test-harness"))]
    stats: PolicyStats,
}

/// Stack-only scan state. Insertions/hits must not interleave an owner-locked scan.
pub(crate) struct Scan {
    remaining: usize,
    proposals: usize,
    epoch: u64,
    #[cfg(any(test, feature = "test-harness"))]
    cursor: Option<usize>,
    #[cfg(any(test, feature = "test-harness"))]
    probation_exhausted: bool,
    #[cfg(any(test, feature = "test-harness"))]
    target: u64,
}

impl Policy {
    pub(crate) fn clock() -> Self {
        Self::new(PolicyKind::Clock)
    }

    pub(crate) fn new(kind: PolicyKind) -> Self {
        Self {
            kind,
            entries: Vec::new(),
            positions: HashMap::new(),
            free: None,
            lists: [List::default(), List::default()],
            epoch: 0,
            #[cfg(any(test, feature = "test-harness"))]
            stats: PolicyStats::default(),
        }
    }

    fn entry(&self, index: usize) -> &Entry {
        // All indices originate in the linked resident lists, never external input.
        &self.entries[index]
    }

    fn entry_mut(&mut self, index: usize) -> &mut Entry {
        &mut self.entries[index]
    }

    fn detach(&mut self, index: usize) {
        let entry = self.entry(index);
        let (previous, next, segment, size) = (
            entry.previous,
            entry.next,
            usize::from(entry.protected),
            entry.identity.size,
        );
        if let Some(previous) = previous {
            self.entry_mut(previous).next = next;
        } else {
            self.lists[segment].first = next;
        }
        if let Some(next) = next {
            self.entry_mut(next).previous = previous;
        } else {
            self.lists[segment].last = previous;
        }
        if self.lists[segment].hand == Some(index) {
            self.lists[segment].hand = next.or(self.lists[segment].first);
        }
        self.lists[segment].bytes -= size;
    }

    fn append(&mut self, index: usize, protected: bool) {
        let segment = usize::from(protected);
        let last = self.lists[segment].last;
        let entry = self.entry_mut(index);
        entry.previous = last;
        entry.next = None;
        entry.protected = protected;
        let size = entry.identity.size;
        if let Some(last) = last {
            self.entry_mut(last).next = Some(index);
        } else {
            self.lists[segment].first = Some(index);
        }
        self.lists[segment].last = Some(index);
        self.lists[segment].hand = self.lists[segment].hand.or(Some(index));
        self.lists[segment].bytes = self.lists[segment].bytes.saturating_add(size);
    }

    pub(crate) fn insert(&mut self, identity: ObjectIdentity) {
        if self.positions.contains_key(&identity) {
            return;
        }
        let index = if let Some(index) = self.free {
            self.free = self.entry(index).next;
            index
        } else {
            self.entries.len()
        };
        let entry = Entry {
            identity,
            previous: None,
            next: None,
            protected: false,
            referenced: self.kind == PolicyKind::Clock,
            proposed: 0,
        };
        if index == self.entries.len() {
            self.entries.push(entry);
        } else {
            self.entries[index] = entry;
        }
        self.positions.insert(identity, index);
        self.append(index, false);
    }

    pub(crate) fn hit(&mut self, identity: &ObjectIdentity) {
        let Some(&index) = self.positions.get(identity) else {
            return;
        };
        #[cfg(any(test, feature = "test-harness"))]
        {
            self.stats.demand_hits += 1;
        }
        match self.kind {
            PolicyKind::Clock => self.entry_mut(index).referenced = true,
            #[cfg(any(test, feature = "test-harness"))]
            PolicyKind::Fifo => {}
            #[cfg(any(test, feature = "test-harness"))]
            PolicyKind::Lru => {
                if self.lists[0].last != Some(index) {
                    self.detach(index);
                    self.append(index, false);
                }
            }
            #[cfg(any(test, feature = "test-harness"))]
            PolicyKind::SegmentedClock => {
                if !self.entry(index).protected {
                    self.detach(index);
                    self.append(index, true);
                }
                self.entry_mut(index).referenced = true;
            }
        }
    }

    pub(crate) fn remove(&mut self, identity: &ObjectIdentity) {
        if let Some(index) = self.positions.remove(identity) {
            self.detach(index);
            self.entry_mut(index).next = self.free;
            self.free = Some(index);
            #[cfg(any(test, feature = "test-harness"))]
            {
                self.stats.removals += 1;
            }
        }
    }

    pub(crate) fn skipped(&mut self, _identity: &ObjectIdentity) {
        // Rejection is neither removal nor reuse. Keep all ranking state intact.
        #[cfg(any(test, feature = "test-harness"))]
        {
            self.stats.skipped_notifications += 1;
        }
    }

    pub(crate) fn begin_scan(&mut self, requested: u64, evictable_bytes: u64) -> Scan {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            for entry in &mut self.entries {
                entry.proposed = 0;
            }
            self.epoch = 1;
        }
        Scan {
            remaining: if requested == 0 || evictable_bytes == 0 {
                0
            } else {
                self.positions.len().saturating_mul(2)
            },
            proposals: 0,
            epoch: self.epoch,
            #[cfg(any(test, feature = "test-harness"))]
            cursor: self.lists[0].first,
            #[cfg(any(test, feature = "test-harness"))]
            probation_exhausted: false,
            // Avoid multiplication overflow without changing the 80% target.
            #[cfg(any(test, feature = "test-harness"))]
            target: evictable_bytes / 5 * 4 + evictable_bytes % 5 * 4 / 5,
        }
    }

    pub(crate) fn next_candidate(&mut self, scan: &mut Scan) -> Option<ObjectIdentity> {
        while scan.remaining > 0 && scan.proposals < MAX_CANDIDATES {
            let index = match self.kind {
                PolicyKind::Clock => self.lists[0].hand?,
                #[cfg(any(test, feature = "test-harness"))]
                PolicyKind::Fifo | PolicyKind::Lru => scan.cursor?,
                #[cfg(any(test, feature = "test-harness"))]
                PolicyKind::SegmentedClock => {
                    // Rebalance excess protection with CLOCK second chances. If
                    // probation is empty, protection cannot prevent reclamation.
                    if (self.lists[1].bytes > scan.target
                        || self.lists[0].first.is_none()
                        || scan.probation_exhausted)
                        && let Some(index) = self.lists[1].hand
                    {
                        scan.remaining -= 1;
                        self.inspect();
                        self.advance(index, 1);
                        if self.entry(index).referenced {
                            self.entry_mut(index).referenced = false;
                        } else {
                            self.detach(index);
                            scan.probation_exhausted = false;
                            self.append(index, false);
                        }
                        continue;
                    }
                    self.lists[0].hand?
                }
            };
            scan.remaining -= 1;
            self.inspect();
            #[cfg(any(test, feature = "test-harness"))]
            {
                scan.cursor = self.entry(index).next;
            }
            self.advance(index, 0);
            if self.entry(index).proposed == scan.epoch {
                #[cfg(any(test, feature = "test-harness"))]
                {
                    scan.probation_exhausted = true;
                }
                continue;
            }
            if self.kind == PolicyKind::Clock && self.entry(index).referenced {
                self.entry_mut(index).referenced = false;
                continue;
            }
            self.entry_mut(index).proposed = scan.epoch;
            scan.proposals += 1;
            #[cfg(any(test, feature = "test-harness"))]
            {
                self.stats.candidate_proposals += 1;
            }
            return Some(self.entry(index).identity);
        }
        None
    }

    fn advance(&mut self, index: usize, segment: usize) {
        self.lists[segment].hand = self.entry(index).next.or(self.lists[segment].first);
    }

    fn inspect(&mut self) {
        #[cfg(any(test, feature = "test-harness"))]
        {
            self.stats.candidate_inspections += 1;
        }
    }

    #[cfg(any(test, feature = "test-harness"))]
    pub(crate) fn stats(&self) -> PolicyStats {
        let mut stats = self.stats;
        stats.resident_entries = self.positions.len();
        // HashMap capacity is usable entries, not allocated buckets. This lower
        // estimate excludes control bytes, bucket slack, alignment and allocator
        // headers. Vec capacities include vacant/free slots. No RSS claim.
        stats.memory_estimate_bytes = std::mem::size_of::<Self>()
            + self.entries.capacity() * std::mem::size_of::<Entry>()
            + self.positions.capacity() * std::mem::size_of::<(ObjectIdentity, usize)>();
        stats
    }
}

#[cfg(test)]
mod tests;
