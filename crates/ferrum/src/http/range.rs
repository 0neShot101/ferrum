//! `Range` header evaluation (`PLAN.md` §3 Range and caching contract).
//!
//! Only one `bytes` range is honoured. Anything else (multiple ranges, other
//! units, malformed or overflowing values) is ignored and answered with the
//! full representation; a syntactically valid but unsatisfiable range, or the
//! suffix `-0`, answers 416.

/// Result of evaluating a `Range` header against an object of known length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeOutcome {
    /// Serve `start..=end` (clipped to the object).
    Partial { start: u64, end: u64 },
    /// 416 with `Content-Range: bytes */N`.
    Unsatisfiable,
    /// Serve the full representation with 200.
    Ignore,
}

/// Evaluates `header` for an object of `size` bytes.
pub fn evaluate(header: &str, size: u64) -> RangeOutcome {
    if size == 0 {
        return RangeOutcome::Ignore;
    }
    let Some(spec) = header.strip_prefix("bytes=") else {
        return RangeOutcome::Ignore;
    };
    let spec = spec.trim();
    if spec.is_empty() || spec.contains(',') {
        return RangeOutcome::Ignore;
    }
    let Some((first, last)) = spec.split_once('-') else {
        return RangeOutcome::Ignore;
    };
    let (first, last) = (first.trim(), last.trim());
    let last_byte = size - 1;
    match (parse_number(first), parse_number(last)) {
        // bytes=a-b
        (Some(Some(start)), Some(Some(end))) => {
            if start > end {
                return RangeOutcome::Ignore;
            }
            if start > last_byte {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial {
                start,
                end: end.min(last_byte),
            }
        }
        // bytes=a-
        (Some(Some(start)), Some(None)) => {
            if start > last_byte {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial {
                start,
                end: last_byte,
            }
        }
        // bytes=-n
        (Some(None), Some(Some(suffix))) => {
            if suffix == 0 {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial {
                start: size.saturating_sub(suffix),
                end: last_byte,
            }
        }
        _ => RangeOutcome::Ignore,
    }
}

/// `Some(None)` for an empty field, `Some(Some(n))` for a decimal, `None` when
/// malformed or overflowing.
fn parse_number(text: &str) -> Option<Option<u64>> {
    if text.is_empty() {
        return Some(None);
    }
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_byte_only() {
        assert_eq!(
            evaluate("bytes=0-0", 682),
            RangeOutcome::Partial { start: 0, end: 0 }
        );
    }

    #[test]
    fn open_ended_and_suffix_are_clipped() {
        assert_eq!(
            evaluate("bytes=100-", 682),
            RangeOutcome::Partial {
                start: 100,
                end: 681
            }
        );
        assert_eq!(
            evaluate("bytes=600-9999", 682),
            RangeOutcome::Partial {
                start: 600,
                end: 681
            }
        );
        assert_eq!(
            evaluate("bytes=-10", 682),
            RangeOutcome::Partial {
                start: 672,
                end: 681
            }
        );
        assert_eq!(
            evaluate("bytes=-9999", 682),
            RangeOutcome::Partial { start: 0, end: 681 }
        );
    }

    #[test]
    fn unsatisfiable_cases() {
        assert_eq!(evaluate("bytes=682-", 682), RangeOutcome::Unsatisfiable);
        assert_eq!(evaluate("bytes=700-800", 682), RangeOutcome::Unsatisfiable);
        assert_eq!(evaluate("bytes=-0", 682), RangeOutcome::Unsatisfiable);
    }

    #[test]
    fn ignored_cases() {
        assert_eq!(evaluate("bytes=0-0,2-3", 682), RangeOutcome::Ignore);
        assert_eq!(evaluate("items=0-0", 682), RangeOutcome::Ignore);
        assert_eq!(evaluate("bytes=5-2", 682), RangeOutcome::Ignore);
        assert_eq!(evaluate("bytes=a-b", 682), RangeOutcome::Ignore);
        assert_eq!(evaluate("bytes=-", 682), RangeOutcome::Ignore);
        assert_eq!(evaluate("bytes=", 682), RangeOutcome::Ignore);
        assert_eq!(
            evaluate("bytes=99999999999999999999-", 682),
            RangeOutcome::Ignore
        );
        assert_eq!(evaluate("bytes=0-0", 0), RangeOutcome::Ignore);
    }
}
