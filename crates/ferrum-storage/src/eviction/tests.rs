use super::*;
use ferrum_apt::digest::Sha256Digest;
use std::collections::HashSet;

fn identity(number: u32, size: u64) -> ObjectIdentity {
    ObjectIdentity {
        sha256: Sha256Digest::of(&number.to_le_bytes()),
        size,
    }
}

#[test]
fn fifo_ignores_hits_and_lru_is_exact_across_slot_reuse() {
    for (kind, first) in [(PolicyKind::Fifo, 0), (PolicyKind::Lru, 1)] {
        let mut policy = Policy::new(kind);
        for number in 0..4 {
            policy.insert(identity(number, 1));
        }
        policy.hit(&identity(0, 1));
        let mut scan = policy.begin_scan(1, 4);
        assert_eq!(policy.next_candidate(&mut scan), Some(identity(first, 1)));
        policy.remove(&identity(first, 1));
        policy.insert(identity(4, 1));
        let mut scan = policy.begin_scan(100, 4);
        let mut order = Vec::new();
        while let Some(candidate) = policy.next_candidate(&mut scan) {
            order.push(candidate);
        }
        let expected = if kind == PolicyKind::Fifo {
            [1, 2, 3, 4]
        } else {
            [2, 3, 0, 4]
        };
        assert_eq!(order, expected.map(|number| identity(number, 1)));
    }
}

#[test]
fn clock_second_chance_and_early_stop_do_not_manufacture_hits() {
    let mut policy = Policy::clock();
    for number in 0..3 {
        policy.insert(identity(number, 1));
    }
    let mut scan = policy.begin_scan(1, 3);
    assert_eq!(policy.next_candidate(&mut scan), Some(identity(0, 1)));
    assert_eq!(policy.stats().candidate_inspections, 4);
    policy.remove(&identity(0, 1));
    let mut scan = policy.begin_scan(1, 2);
    assert_eq!(policy.next_candidate(&mut scan), Some(identity(1, 1)));
    assert_eq!(policy.stats().candidate_inspections, 5);
    assert_eq!(policy.stats().demand_hits, 0);
}

#[test]
fn segmented_promotes_only_demand_and_uses_owner_byte_target() {
    let mut policy = Policy::new(PolicyKind::SegmentedClock);
    for number in 0..5 {
        policy.insert(identity(number, 10));
    }
    policy.hit(&identity(0, 10));
    policy.hit(&identity(1, 10));
    let mut scan = policy.begin_scan(10, 50);
    assert_eq!(scan.target, 40);
    assert_eq!(policy.next_candidate(&mut scan), Some(identity(2, 10)));
    policy.skipped(&identity(2, 10));
    assert_eq!(policy.lists[1].bytes, 20);
    // Owner hint shrinks: protection is not 80% of resident bytes.
    let mut scan = policy.begin_scan(10, 10);
    assert_eq!(scan.target, 8);
    assert_eq!(policy.next_candidate(&mut scan), Some(identity(3, 10)));
    assert_eq!(policy.lists[1].bytes, 0);
    assert_eq!(policy.stats().demand_hits, 2);
}

#[test]
fn protected_clock_second_chances_are_bounded() {
    let mut policy = Policy::new(PolicyKind::SegmentedClock);
    policy.insert(identity(0, 10));
    policy.hit(&identity(0, 10));
    let mut scan = policy.begin_scan(10, 10);
    // Two inspections give the protected entry its chance then demote it;
    // the next maintenance round may propose it, never a third pass here.
    assert_eq!(policy.next_candidate(&mut scan), None);
    assert_eq!(policy.stats().candidate_inspections, 2);
    let mut scan = policy.begin_scan(10, 10);
    assert_eq!(policy.next_candidate(&mut scan), Some(identity(0, 10)));
}

#[test]
fn rejected_candidates_remain_resident_and_scans_never_duplicate() {
    for kind in [
        PolicyKind::Fifo,
        PolicyKind::Clock,
        PolicyKind::Lru,
        PolicyKind::SegmentedClock,
    ] {
        let mut policy = Policy::new(kind);
        for number in 0..2000 {
            policy.insert(identity(number, 1));
        }
        let mut scan = policy.begin_scan(u64::MAX, 2000);
        let mut seen = HashSet::new();
        while let Some(candidate) = policy.next_candidate(&mut scan) {
            assert!(seen.insert(candidate));
            policy.skipped(&candidate);
        }
        assert!(seen.len() <= MAX_CANDIDATES);
        assert!(policy.stats().candidate_inspections <= 4000);
        assert_eq!(policy.stats().resident_entries, 2000);
        assert_eq!(policy.stats().demand_hits, 0);
        let mut scan = policy.begin_scan(0, 2000);
        assert_eq!(policy.next_candidate(&mut scan), None);
        let mut scan = policy.begin_scan(1, 0);
        assert_eq!(policy.next_candidate(&mut scan), None);
    }
}

#[test]
fn vacant_slots_do_not_consume_scan_budget_or_reuse_events() {
    for kind in [
        PolicyKind::Fifo,
        PolicyKind::Clock,
        PolicyKind::Lru,
        PolicyKind::SegmentedClock,
    ] {
        let mut policy = Policy::new(kind);
        for number in 0..2000 {
            policy.insert(identity(number, 1));
        }
        for number in 0..1999 {
            policy.remove(&identity(number, 1));
        }
        // Re-inserting a resident object (e.g. deduplicated fill completion)
        // does not count as a second independent demand.
        policy.insert(identity(1999, 1));
        let inspected = policy.stats().candidate_inspections;
        let mut scan = policy.begin_scan(1, 1);
        assert_eq!(policy.next_candidate(&mut scan), Some(identity(1999, 1)));
        assert_eq!(policy.next_candidate(&mut scan), None);
        assert!(policy.stats().candidate_inspections - inspected <= 2);
        assert_eq!(policy.stats().demand_hits, 0);
    }
}
