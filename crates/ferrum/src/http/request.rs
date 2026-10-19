//! Request admission rules (`PLAN.md` §3.1-§3.2): method, target and limits.

use axum::http::{Method, Uri};
use ferrum_apt::path::RepositoryPath;

use crate::config::MAX_REQUEST_PATH_BYTES;

/// Supported read methods.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestMethod {
    Get,
    Head,
}

/// A request that passed method/target validation.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidRequest {
    pub method: RequestMethod,
    pub path: RepositoryPath,
}

/// Why a request was refused before resolution; each maps to one status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// 405 with `Allow: GET, HEAD`.
    MethodNotAllowed,
    /// 400: query strings never become cache keys.
    QueryString,
    /// 414: raw target longer than 8 KiB.
    PathTooLong,
    /// 404: the target is not a valid repository path.
    InvalidPath,
}

/// Validates method and request target.
///
/// # Errors
/// [`Rejection`] in evaluation order: method, query, length, path grammar.
pub fn validate(method: &Method, uri: &Uri) -> Result<ValidRequest, Rejection> {
    let method = match *method {
        Method::GET => RequestMethod::Get,
        Method::HEAD => RequestMethod::Head,
        _ => return Err(Rejection::MethodNotAllowed),
    };
    if uri.query().is_some() {
        return Err(Rejection::QueryString);
    }
    let raw = uri.path();
    if raw.len() > MAX_REQUEST_PATH_BYTES {
        return Err(Rejection::PathTooLong);
    }
    let without_root = raw.strip_prefix('/').ok_or(Rejection::InvalidPath)?;
    let path =
        RepositoryPath::parse_request_target(without_root).map_err(|_| Rejection::InvalidPath)?;
    Ok(ValidRequest { method, path })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn uri(text: &str) -> Uri {
        text.parse().expect("uri")
    }

    #[test]
    fn accepts_get_and_head_only() {
        assert!(validate(&Method::GET, &uri("/fixture/dists/ferrum-test/InRelease")).is_ok());
        let head = validate(&Method::HEAD, &uri("/fixture/pool/a.deb")).expect("head");
        assert_eq!(head.method, RequestMethod::Head);
        assert_eq!(
            validate(&Method::POST, &uri("/fixture/pool/a.deb")),
            Err(Rejection::MethodNotAllowed)
        );
    }

    #[test]
    fn rejects_queries_long_and_malformed_paths() {
        assert_eq!(
            validate(&Method::GET, &uri("/fixture/pool/a.deb?x=1")),
            Err(Rejection::QueryString)
        );
        let long = format!("/fixture/{}", "a".repeat(MAX_REQUEST_PATH_BYTES));
        assert_eq!(
            validate(&Method::GET, &uri(&long)),
            Err(Rejection::PathTooLong)
        );
        assert_eq!(
            validate(&Method::GET, &uri("/fixture/../etc/passwd")),
            Err(Rejection::InvalidPath)
        );
        assert_eq!(
            validate(&Method::GET, &uri("/fixture/pool%2Fa.deb")),
            Err(Rejection::InvalidPath)
        );
        assert_eq!(
            validate(&Method::GET, &uri("/")),
            Err(Rejection::InvalidPath)
        );
    }
}
