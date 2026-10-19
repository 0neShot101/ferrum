//! Representation responses: validators, preconditions, ranges and error
//! envelopes (`PLAN.md` §3.4, §3 Range and caching contract).
//!
//! Preconditions are evaluated in RFC 9110 order against the pinned
//! descriptor: `If-Match`, then `If-None-Match`, then `If-Range`/`Range`. No
//! `Last-Modified` is emitted, so date preconditions are ignored. Errors never
//! carry a representation and always use `Cache-Control: no-store`.

use axum::body::Body;
use axum::http::header::{
    ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG,
    HeaderMap, HeaderValue, IF_MATCH, IF_NONE_MATCH, IF_RANGE, RANGE, RETRY_AFTER,
};
use axum::http::{Response, StatusCode};
use ferrum_apt::digest::ObjectIdentity;

use super::range::{self, RangeOutcome};
use super::request::RequestMethod;
use crate::sync::CacheClass;

/// `Retry-After` value on every 503.
pub const RETRY_AFTER_SECONDS: &str = "5";
const NO_STORE: &str = "no-store";
const OCTET_STREAM: &str = "application/octet-stream";

/// The pinned descriptor a response is built from.
#[derive(Debug, Clone, Copy)]
pub struct Representation {
    pub identity: ObjectIdentity,
    pub class: CacheClass,
}

impl Representation {
    /// Strong validator over the exact bytes: `"sha256-<hex>"`.
    pub fn etag(&self) -> String {
        format!("\"sha256-{}\"", self.identity.sha256)
    }
}

/// What to send after preconditions and Range were evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponsePlan {
    /// 412 (`If-Match` failed).
    PreconditionFailed,
    /// 304 with validators and cache headers, no body.
    NotModified,
    /// 200 with the whole representation (HEAD: headers only).
    Full,
    /// 206 with `start..=end`.
    Partial { start: u64, end: u64 },
    /// 416 with `Content-Range: bytes */N`.
    RangeNotSatisfiable,
}

/// Evaluates preconditions and Range for `representation`.
pub fn plan(
    method: RequestMethod,
    headers: &HeaderMap,
    representation: &Representation,
) -> ResponsePlan {
    let etag = representation.etag();
    let if_match = headers.get_all(IF_MATCH);
    if if_match.iter().next().is_some()
        && !if_match
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|value| strong_match(value, &etag))
    {
        return ResponsePlan::PreconditionFailed;
    }
    if headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| weak_match(value, &etag))
    {
        return ResponsePlan::NotModified;
    }
    if method == RequestMethod::Head {
        return ResponsePlan::Full;
    }
    if headers.get_all(RANGE).iter().count() > 1 || headers.get_all(IF_RANGE).iter().count() > 1 {
        return ResponsePlan::Full;
    }
    let Some(range_header) = header_text(headers, &RANGE) else {
        return ResponsePlan::Full;
    };
    if let Some(if_range) = header_text(headers, &IF_RANGE)
        && if_range.trim() != etag
    {
        return ResponsePlan::Full;
    }
    match range::evaluate(range_header, representation.identity.size) {
        RangeOutcome::Partial { start, end } => ResponsePlan::Partial { start, end },
        RangeOutcome::Unsatisfiable => ResponsePlan::RangeNotSatisfiable,
        RangeOutcome::Ignore => ResponsePlan::Full,
    }
}

/// Builds the 200/206 (or HEAD) response; `body` must cover exactly the planned
/// bytes (empty for HEAD).
pub fn representation(
    representation: &Representation,
    plan: ResponsePlan,
    body: Body,
) -> Response<Body> {
    let size = representation.identity.size;
    let (status, start, end) = match plan {
        ResponsePlan::Partial { start, end } => (StatusCode::PARTIAL_CONTENT, start, end),
        _ => (StatusCode::OK, 0, size.saturating_sub(1)),
    };
    let length = if size == 0 {
        0
    } else {
        end.saturating_sub(start).saturating_add(1)
    };
    let mut builder = Response::builder()
        .status(status)
        .header(ETAG, representation.etag())
        .header(ACCEPT_RANGES, "bytes")
        .header(CACHE_CONTROL, representation.class.cache_control())
        .header(CONTENT_TYPE, OCTET_STREAM)
        .header(CONTENT_LENGTH, length);
    if status == StatusCode::PARTIAL_CONTENT {
        builder = builder.header(CONTENT_RANGE, format!("bytes {start}-{end}/{size}"));
    }
    builder
        .body(body)
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 304 with the validators and cache policy of the selected representation.
pub fn not_modified(representation: &Representation) -> Response<Body> {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(ETAG, representation.etag())
        .header(CACHE_CONTROL, representation.class.cache_control())
        .body(Body::empty())
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR))
}

/// 416 with `Content-Range: bytes */N` and an empty body.
pub fn range_not_satisfiable(size: u64) -> Response<Body> {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(CONTENT_RANGE, format!("bytes */{size}"))
        .header(CACHE_CONTROL, NO_STORE)
        .header(CONTENT_LENGTH, 0)
        .body(Body::empty())
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Empty error response with `Cache-Control: no-store`; 503 adds `Retry-After`.
pub fn error(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static(NO_STORE));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    if status == StatusCode::SERVICE_UNAVAILABLE {
        headers.insert(RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_SECONDS));
    }
    response
}

/// 503 `Retry-After: 5`.
pub fn service_unavailable() -> Response<Body> {
    error(StatusCode::SERVICE_UNAVAILABLE)
}

/// Persistent provider allowance refusal is not a five-second capacity retry.
pub fn budget_unavailable() -> Response<Body> {
    let mut response = service_unavailable();
    response
        .headers_mut()
        .insert(RETRY_AFTER, HeaderValue::from_static("3600"));
    response
}

/// 405 with `Allow: GET, HEAD`.
pub fn method_not_allowed() -> Response<Body> {
    let mut response = error(StatusCode::METHOD_NOT_ALLOWED);
    response
        .headers_mut()
        .insert(ALLOW, HeaderValue::from_static("GET, HEAD"));
    response
}

fn header_text<'a>(headers: &'a HeaderMap, name: &axum::http::HeaderName) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn entity_tags(list: &str) -> impl Iterator<Item = &str> {
    list.split(',').map(str::trim).filter(|tag| !tag.is_empty())
}

/// RFC 9110 strong comparison: `*` or an identical strong tag.
fn strong_match(list: &str, etag: &str) -> bool {
    list.trim() == "*" || entity_tags(list).any(|tag| tag == etag)
}

/// RFC 9110 weak comparison: `*` or equal opaque tags ignoring `W/`.
fn weak_match(list: &str, etag: &str) -> bool {
    list.trim() == "*" || entity_tags(list).any(|tag| tag.strip_prefix("W/").unwrap_or(tag) == etag)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use ferrum_apt::digest::Sha256Digest;

    fn representation() -> Representation {
        Representation {
            identity: ObjectIdentity {
                sha256: Sha256Digest::of(b"fixture"),
                size: 682,
            },
            class: CacheClass::Package,
        }
    }

    fn headers(pairs: &[(&'static axum::http::HeaderName, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(*name, HeaderValue::from_str(value).expect("header"));
        }
        map
    }

    #[test]
    fn etag_is_strong_sha256() {
        let etag = representation().etag();
        assert!(etag.starts_with("\"sha256-"));
        assert!(etag.ends_with('"'));
        assert_eq!(etag.len(), 2 + 7 + 64);
    }

    #[test]
    fn if_match_precedes_everything() {
        let representation = representation();
        let etag = representation.etag();
        let map = headers(&[(&IF_MATCH, "\"other\""), (&IF_NONE_MATCH, &etag)]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::PreconditionFailed
        );
        let weak = format!("W/{etag}");
        let map = headers(&[(&IF_MATCH, &weak)]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::PreconditionFailed
        );
        let map = headers(&[(&IF_MATCH, "*"), (&RANGE, "bytes=0-0")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Partial { start: 0, end: 0 }
        );
    }

    #[test]
    fn if_none_match_precedes_range() {
        let representation = representation();
        let etag = representation.etag();
        let list = format!("\"x\", W/{etag}");
        let map = headers(&[(&IF_NONE_MATCH, &list), (&RANGE, "bytes=0-0")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::NotModified
        );
        let map = headers(&[(&IF_NONE_MATCH, "*")]);
        assert_eq!(
            plan(RequestMethod::Head, &map, &representation),
            ResponsePlan::NotModified
        );
        let map = headers(&[(&IF_NONE_MATCH, "\"x\"")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Full
        );
    }

    #[test]
    fn range_table() {
        let representation = representation();
        let map = headers(&[(&RANGE, "bytes=0-0")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Partial { start: 0, end: 0 }
        );
        let map = headers(&[(&RANGE, "bytes=-0")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::RangeNotSatisfiable
        );
        let map = headers(&[(&RANGE, "bytes=0-0,1-1")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Full
        );
        let map = headers(&[(&RANGE, "bytes=0-0")]);
        assert_eq!(
            plan(RequestMethod::Head, &map, &representation),
            ResponsePlan::Full
        );
    }

    #[test]
    fn if_range_only_honours_our_strong_tag() {
        let representation = representation();
        let etag = representation.etag();
        let map = headers(&[(&RANGE, "bytes=0-0"), (&IF_RANGE, &etag)]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Partial { start: 0, end: 0 }
        );
        let weak = format!("W/{etag}");
        let map = headers(&[(&RANGE, "bytes=0-0"), (&IF_RANGE, &weak)]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Full
        );
        let map = headers(&[(&RANGE, "bytes=0-0"), (&IF_RANGE, "\"other\"")]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Full
        );
        let map = headers(&[
            (&RANGE, "bytes=0-0"),
            (&IF_RANGE, "Sat, 17 Oct 2026 12:00:00 GMT"),
        ]);
        assert_eq!(
            plan(RequestMethod::Get, &map, &representation),
            ResponsePlan::Full
        );
    }

    #[test]
    fn response_headers() {
        let representation = representation();
        let response = super::representation(
            &representation,
            ResponsePlan::Partial { start: 0, end: 0 },
            Body::empty(),
        );
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()[CONTENT_RANGE], "bytes 0-0/682");
        assert_eq!(response.headers()[CONTENT_LENGTH], "1");
        assert_eq!(response.headers()[ACCEPT_RANGES], "bytes");
        assert_eq!(response.headers()[CACHE_CONTROL], "public, max-age=86400");

        let full = super::representation(&representation, ResponsePlan::Full, Body::empty());
        assert_eq!(full.status(), StatusCode::OK);
        assert_eq!(full.headers()[CONTENT_LENGTH], "682");
        assert!(full.headers().get(CONTENT_RANGE).is_none());

        let unavailable = service_unavailable();
        assert_eq!(unavailable.headers()[RETRY_AFTER], "5");
        assert_eq!(unavailable.headers()[CACHE_CONTROL], "no-store");
        let not_found = error(StatusCode::NOT_FOUND);
        assert!(not_found.headers().get(RETRY_AFTER).is_none());
        assert_eq!(method_not_allowed().headers()[ALLOW], "GET, HEAD");
        assert_eq!(
            range_not_satisfiable(682).headers()[CONTENT_RANGE],
            "bytes */682"
        );
    }
}
