use std::{sync::LazyLock, time::Duration};

pub(crate) mod heuristics;

use async_smtp::{
    EmailAddress, SmtpClient, SmtpTransport,
    commands::{MailCommand, RcptCommand},
    extension::ClientId,
    response::Response,
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
        use async_smtp::error::Error::*;
        match result {
            Ok(()) => Success,
            Err(error) => match error {
                Error::InvalidAddressFormat => Failure(FailureReason::InvalidAddressFormat),
                Error::DnsResolverError(e) => {
                    if e.is_no_records_found() {
                        Failure(FailureReason::NoMxRecords)
                    } else {
                        Uncertain(UncertaintyReason::DnsResolverError)
                    }
                }
                Error::SmtpError(e) => match e {
                    Transient(r) => Uncertain(UncertaintyReason::NegativeSmtpResponse(r)),
                    Permanent(r) => heuristics::handle_permanent(r),
                    Timeout(_) => Uncertain(UncertaintyReason::Timeout),
                    e => Uncertain(UncertaintyReason::SmtpError(e.to_string())),
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
    /// Got a negative SMTP response
    NegativeSmtpResponse(Response),
    /// Unexpected SMTP error
    SmtpError(String),
    /// Unexpected DNS resolution error
    DnsResolverError,
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

/// Mail servers may respond with
///
/// - `4.1.8 Sender address rejected` (https://www.suped.com/knowledge/email-deliverability/troubleshooting/what-does-smtp-bounce-reason-418-bad-senders-system-address-domain-of-sender-address-does-not-re)
/// - `5.7.27 Sender address has null MX` (https://www.rfc-editor.org/rfc/rfc7505#section-4.2)
/// - SPF rejection as per https://www.rfc-editor.org/rfc/rfc7208
static SENDER_ADDRESS: LazyLock<EmailAddress> =
    LazyLock::new(|| EmailAddress::new("me@thomaszahner.ch".to_owned()).unwrap());

static CLIENT_ID: LazyLock<ClientId> = LazyLock::new(|| ClientId::Domain("example.com.".into()));

async fn verify_mail(mail: &str, record: &MX) -> Result {
    const PORT: u16 = 25;

    let host = record.exchange();
    let stream = BufStream::new(TcpStream::connect(format!("{host}:{PORT}")).await?);
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
    async fn icloud() {
        assert_eq!(check("thomas1@icloud.com").await, CheckResult::Success);

        assert_eq!(
            check("hi@icloud.com").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );

        // 5.1.6 user no longer on system:peter@icloud.com
        assert_eq!(
            check("peter@icloud.com").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );

        // this is intentially considered `Uncertain`
        // 5.2.2 <thomas@icloud.com>: user is over quota
        assert!(matches!(
            check("thomas@icloud.com").await,
            CheckResult::Uncertain(UncertaintyReason::NegativeSmtpResponse(_))
        ));
    }

    #[tokio::test]
    async fn blocklisting() {
        assert!(matches!(
            check("thomas@outlook.com").await,
            CheckResult::Uncertain(UncertaintyReason::NegativeSmtpResponse(_))
        ));

        assert!(matches!(
            check("thomas@hotmail.com").await,
            CheckResult::Uncertain(UncertaintyReason::NegativeSmtpResponse(_))
        ));

        assert_eq!(
            check("thomas@bluewin.ch").await,
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
