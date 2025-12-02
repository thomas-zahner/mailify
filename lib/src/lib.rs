use std::{sync::LazyLock, time::Duration};

use async_smtp::{
    EmailAddress, SmtpClient, SmtpTransport,
    commands::{MailCommand, RcptCommand},
    extension::ClientId,
};
use hickory_resolver::{ResolveError, proto::rr::rdata::MX};
use tokio::{io::BufStream, net::TcpStream, time::timeout};

/// Email check result
#[derive(Debug, PartialEq)]
pub enum CheckResult {
    /// Email address exists
    Success,
    /// Unable to determine with certainty if address exists
    Uncertain(UncertaintyReason),
    /// Email address does not exist
    Failure(FailureReason),
}

impl From<Result> for CheckResult {
    fn from(result: Result) -> Self {
        use CheckResult::*;
        match result {
            Ok(()) => Success,
            Err(error) => match error {
                Error::InvalidAddressFormat => Failure(FailureReason::InvalidAddressFormat),
                Error::DnsResolverError(e) => {
                    if e.is_no_records_found() {
                        Failure(FailureReason::NoMxRecords)
                    } else {
                        todo!("{e:?}")
                    }
                }
                Error::SmtpError(e) => match e {
                    async_smtp::error::Error::Transient(_) => {
                        Uncertain(UncertaintyReason::TransientResponse)
                    }
                    async_smtp::error::Error::Permanent(response) => {
                        dbg!(&response);
                        let is_blocklisted = response
                            .message
                            .iter()
                            .map(|line| line.to_lowercase())
                            .any(|line| line.contains("listing") || line.contains("spam"));

                        if is_blocklisted {
                            return Uncertain(UncertaintyReason::Blocklisted);
                        }

                        if !response.is_positive() {
                            Failure(FailureReason::NoSuchAddress)
                        } else {
                            todo!("permanent positive error response?")
                        }
                    }
                    _ => todo!("{e:?}"),
                },
                Error::IoError(e) => todo!("{e:?}"),
                Error::NoMxRecords => Failure(FailureReason::NoMxRecords),
                Error::Timeout => Uncertain(UncertaintyReason::Timeout),
            },
        }
    }
}

/// There are situations where we cannot determine with
/// certainty if an address exists. This is mostly due
/// to blocklists and restrictive measures by email servers.
#[derive(Debug, PartialEq)]
pub enum UncertaintyReason {
    /// Request timed out.
    /// A common (not very nice) practice of blocklisting from mail servers
    /// is to not send any reply. So it is probable that we got blocklisted.
    Timeout,
    /// Server blocklisted our request.
    /// This normally happens because the server doesn't trust our IP address.
    Blocklisted,
    /// Got a non-permanent SMTP response, which might change upon retry
    TransientResponse,
}

#[derive(Debug, PartialEq)]
pub enum FailureReason {
    /// The mail address format is invalid
    InvalidAddressFormat,
    /// The domain has no MX records
    NoMxRecords,
    /// The mail server does not accept the address
    NoSuchAddress,
}

#[derive(Debug)]
enum Error {
    InvalidAddressFormat,
    DnsResolverError(ResolveError),
    SmtpError(async_smtp::error::Error),
    IoError(std::io::Error),
    NoMxRecords,
    Timeout,
}

impl From<ResolveError> for Error {
    fn from(error: ResolveError) -> Self {
        Self::DnsResolverError(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error)
    }
}

impl From<async_smtp::error::Error> for Error {
    fn from(error: async_smtp::error::Error) -> Self {
        Self::SmtpError(error)
    }
}

type Result<T = ()> = std::result::Result<T, Error>;

const TIMEOUT: Duration = Duration::from_secs(10);

/// Check if the given email address exists
/// and is setup to receive messages, without sending
/// a message.
pub async fn check(mail: &str) -> CheckResult {
    check_inner(mail).await.into()
}

async fn check_inner(mail: &str) -> Result {
    let (local_part, domain) = mail.rsplit_once('@').ok_or(Error::InvalidAddressFormat)?;

    if local_part.is_empty() || domain.is_empty() {
        return Err(Error::InvalidAddressFormat);
    }

    let record = first_dns_record(domain).await?;
    timeout(TIMEOUT, verify_mail(mail, &record))
        .await
        .map_err(|_| Error::Timeout)?
}

static SENDER_ADDRESS: LazyLock<EmailAddress> =
    LazyLock::new(|| EmailAddress::new("me@thomaszahner.ch".to_owned()).unwrap());

static CLIENT_ID: LazyLock<ClientId> =
    LazyLock::new(|| ClientId::Domain("mailify.example.com.".into()));

async fn verify_mail(mail: &str, record: &MX) -> Result {
    const PORT: u16 = 25;

    let host = record.exchange();
    let stream = BufStream::new(TcpStream::connect(format!("{host}:{PORT}")).await?);
    dbg!("didn't reach here with wifi hotspot");
    let client = SmtpClient::new();
    let mut transport = SmtpTransport::new(client, stream).await?;

    transport.get_mut().ehlo(CLIENT_ID.clone()).await?;

    transport
        .get_mut()
        .command(MailCommand::new(Some(SENDER_ADDRESS.clone()), vec![]))
        .await?;

    let mail = EmailAddress::new(mail.into()).map_err(|_| Error::InvalidAddressFormat)?;
    transport
        .get_mut()
        .command(RcptCommand::new(mail, vec![]))
        .await?;

    Ok(())
}

async fn first_dns_record(domain: &str) -> Result<MX> {
    lookup_dns(domain)
        .await?
        .first()
        .cloned()
        .ok_or(Error::NoMxRecords)
}

async fn lookup_dns(domain: &str) -> Result<Vec<MX>> {
    let mut records: Vec<_> = hickory_resolver::Resolver::builder_tokio()?
        .build()
        .mx_lookup(domain)
        .await?
        .into_iter()
        .collect();

    records.sort_by_key(|r| r.preference());

    Ok(records)
}

#[cfg(test)]
mod tests {
    use crate::{CheckResult, FailureReason, UncertaintyReason};

    use super::check;

    #[tokio::test]
    async fn invalid_format() {
        let expected = CheckResult::Failure(FailureReason::InvalidAddressFormat);
        assert_eq!(check("some text").await, expected);
        assert_eq!(check("@").await, expected);
        assert_eq!(check("local-part@").await, expected);
        assert_eq!(check("@domain").await, expected);
    }

    #[tokio::test]
    async fn unknown_host() {
        assert_eq!(
            check("hi@unknownHost").await,
            CheckResult::Failure(FailureReason::NoMxRecords)
        );

        assert_eq!(
            check("hi@domainReallyDoesNotExist.org").await,
            CheckResult::Failure(FailureReason::NoMxRecords)
        );
    }

    #[tokio::test]
    async fn detects_my_domain_as_invalid() {
        assert_eq!(
            check("me@thomaszahner.ch").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn gmail() {
        assert_eq!(check("thomas.zahner@gmail.com").await, CheckResult::Success);
        assert_eq!(
            check("alice@gmail.com").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn protonmail() {
        assert_eq!(
            check("thomas.zahner@protonmail.ch").await,
            CheckResult::Success
        );

        assert_eq!(
            check("a@protonmail.ch").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn yandex() {
        assert_eq!(check("thomas@yandex.com").await, CheckResult::Success);
        assert_eq!(
            check("peter@yandex.com").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn tuta() {
        assert_eq!(check("hello@tutao.de").await, CheckResult::Success);
        assert_eq!(check("thomas@tuta.com").await, CheckResult::Success);
        assert_eq!(
            check("a@tuta.com").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn blocklisting() {
        // assert_eq!(check("thomas@outlook.com").await, CheckResult::Success);
        // assert_eq!(check("thomas@hotmail.com").await, CheckResult::Success);
        assert_eq!(
            check("thomas@bluewin.ch").await,
            CheckResult::Uncertain(UncertaintyReason::Blocklisted)
        );
        assert_eq!(
            check("hi@icloud.com").await,
            CheckResult::Uncertain(UncertaintyReason::Blocklisted)
        );
    }

    #[tokio::test]
    async fn false_negatives() {
        // TODO?
        assert_eq!(
            check("a309f2f034590l290@yahoo.com").await,
            CheckResult::Success
        );
        assert_eq!(
            check("a309f2f034590l290@aol.com").await,
            CheckResult::Success
        );
    }
}
