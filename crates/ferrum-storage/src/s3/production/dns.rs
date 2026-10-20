//! Resolver installed in the actual SDK TCP connector, not a DNS preflight.
use super::S3Error;
use aws_smithy_runtime_api::client::dns::{DnsFuture, ResolveDns, ResolveDnsError};
use std::{net::IpAddr, time::Duration};
#[derive(Clone, Debug)]
pub(in crate::s3) struct PublicResolver {
    host: std::sync::Arc<str>,
    #[cfg(test)]
    answers: Option<Vec<IpAddr>>,
}
impl PublicResolver {
    pub(in crate::s3) fn new(host: std::sync::Arc<str>) -> Self {
        Self {
            host,
            #[cfg(test)]
            answers: None,
        }
    }

    #[cfg(test)]
    pub(super) fn scripted(host: &str, answers: Vec<IpAddr>) -> Self {
        Self {
            host: host.into(),
            answers: Some(answers),
        }
    }
}
fn validate(addresses: impl IntoIterator<Item = IpAddr>) -> Result<Vec<IpAddr>, ResolveDnsError> {
    let mut accepted = Vec::new();
    for address in addresses {
        // Reject the entire answer set, never just filter prohibited answers.
        if accepted.len() >= 64 || !crate::recovery::public_ip(address) {
            return Err(ResolveDnsError::new(S3Error::Boundary));
        }
        accepted.push(address);
    }
    if accepted.is_empty() {
        return Err(ResolveDnsError::new(S3Error::Boundary));
    }
    Ok(accepted)
}
impl ResolveDns for PublicResolver {
    fn resolve_dns<'a>(&'a self, name: &'a str) -> DnsFuture<'a> {
        DnsFuture::new(async move {
            if name != self.host.as_ref() {
                return Err(ResolveDnsError::new(S3Error::Boundary));
            }
            #[cfg(test)]
            if let Some(answers) = &self.answers {
                return validate(answers.iter().copied());
            }
            let addresses =
                tokio::time::timeout(Duration::from_secs(3), tokio::net::lookup_host((name, 0)))
                    .await
                    .map_err(ResolveDnsError::new)?
                    .map_err(ResolveDnsError::new)?;
            validate(addresses.map(|address| address.ip()))
        })
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn every_resolution_rejects_private_mapped_and_mixed_answers() {
        for answers in [
            vec!["127.0.0.1"],
            vec!["10.0.0.1"],
            vec!["fc00::1"],
            vec!["::ffff:192.168.1.1"],
            vec!["8.8.8.8", "127.0.0.1"],
            vec![],
        ] {
            let resolver = PublicResolver::scripted(
                "s3.example.org",
                answers
                    .into_iter()
                    .map(|address| address.parse().unwrap())
                    .collect(),
            );
            for _ in 0..2 {
                assert!(resolver.resolve_dns("s3.example.org").await.is_err());
            }
        }
        let resolver = PublicResolver::scripted(
            "s3.example.org",
            vec![
                "8.8.8.8".parse().unwrap(),
                "2606:4700:4700::1111".parse().unwrap(),
            ],
        );
        assert_eq!(
            resolver.resolve_dns("s3.example.org").await.unwrap().len(),
            2
        );
        assert!(resolver.resolve_dns("attacker.invalid").await.is_err());
    }
}
