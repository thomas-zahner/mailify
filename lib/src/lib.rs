//! mailify - identify if a mail address exists.
//! This is the library component of mailify.

#![warn(clippy::all, clippy::pedantic)]

use std::{fmt::Display, sync::LazyLock, time::Duration};

pub(crate) mod heuristics;

use async_smtp::{
    EmailAddress, SmtpClient, SmtpTransport,
    commands::{MailCommand, RcptCommand},
    extension::ClientId,
    response::Response,
};
use hickory_resolver::{ResolveError, proto::rr::rdata::MX};
use tokio::{io::BufStream, net::TcpStream, time};

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

impl Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            CheckResult::Success => "Address exists".into(),
            CheckResult::Uncertain(reason) => format!("Uncertain: {reason}"),
            CheckResult::Failure(reason) => format!("Address does not exist: {reason}"),
        };

        write!(f, "{message}")
    }
}

impl From<Result> for CheckResult {
    fn from(result: Result) -> Self {
        use CheckResult::{Failure, Success, Uncertain};
        use async_smtp::error::Error::{Permanent, Timeout, Transient};
        match result {
            Ok(()) => Success,
            Err(error) => match error {
                Error::InvalidAddressFormat => Failure(FailureReason::InvalidAddressFormat),
                Error::DnsResolution(e) => {
                    if e.is_no_records_found() {
                        Failure(FailureReason::NoMxRecords)
                    } else {
                        Uncertain(UncertaintyReason::DnsResolverError)
                    }
                }
                Error::Smtp(e) => match e {
                    Transient(r) | Permanent(r) => heuristics::from_erroneous(r),
                    Timeout(_) => Uncertain(UncertaintyReason::Timeout),
                    e => Uncertain(UncertaintyReason::SmtpError(e.to_string())),
                },
                Error::Io(e) => Failure(FailureReason::IoError(e.to_string())),
                Error::NoMxRecords => Failure(FailureReason::NoMxRecords),
                Error::Timeout => Uncertain(UncertaintyReason::Timeout),
            },
        }
    }
}

/// There are situations where we cannot determine with
/// certainty if an address exists. This is mostly due
/// to blocklists and restrictive measures by email servers.
#[derive(Debug, PartialEq, Eq)]
pub enum UncertaintyReason {
    /// Request timed out.
    /// Unfortunately, ISPs commonly block outgoing port 25 traffic from their customers.
    /// If you see timeouts for different domains this is the most probable issue.
    /// You could try a different ISP, e.g. by using a VPN or switching the network.
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

#[derive(Debug, PartialEq, Eq)]
pub enum FailureReason {
    /// The mail address format is invalid
    InvalidAddressFormat,
    /// The domain has no MX records
    NoMxRecords,
    /// The mail server does not accept the address
    NoSuchAddress,
    /// Generic IO error
    IoError(String),
}

impl Display for UncertaintyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            UncertaintyReason::Timeout => {
                "Connection timed out. This commonly happens if your ISP blocks outgoing SMTP traffic on port 25.".into()
            }
            UncertaintyReason::Blocklisted => "Mail server has blocklisted our requests.".into(),
            UncertaintyReason::NegativeSmtpResponse(response) => {
                let message  = response.message.join(" ");
                let addendum = if message.is_empty() {
                    String::new()
                } else {
                    format!(": {message}")
                };
                format!("Unclassified negative SMTP response{addendum}")
            }
            UncertaintyReason::SmtpError(e) => format!("Unexpected SMPT error: {e}"),
            UncertaintyReason::DnsResolverError => "Unexpected DNS resolution error".into(),
        };

        write!(f, "{message}")
    }
}

impl Display for FailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            FailureReason::InvalidAddressFormat => {
                "Invalid address format. Expected format: local-part@domain".into()
            }
            FailureReason::NoMxRecords => "No MX records found for domain".into(),
            FailureReason::NoSuchAddress => "Mail server rejects the address".into(),
            FailureReason::IoError(e) => format!("IO error: {e}"),
        };

        write!(f, "{message}")
    }
}

#[derive(Debug)]
enum Error {
    InvalidAddressFormat,
    DnsResolution(ResolveError),
    Smtp(async_smtp::error::Error),
    Io(std::io::Error),
    NoMxRecords,
    Timeout,
}

impl From<ResolveError> for Error {
    fn from(error: ResolveError) -> Self {
        Self::DnsResolution(error)
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<async_smtp::error::Error> for Error {
    fn from(error: async_smtp::error::Error) -> Self {
        Self::Smtp(error)
    }
}

type Result<T = ()> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
/// Customise the behaviour of email checking
pub struct Config {
    /// If a check exceeds the configured timeout duration
    /// it is aborted and resolves to [`CheckResult::Uncertain`] with [`UncertaintyReason::Timeout`].
    pub timeout: Option<Duration>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            timeout: Some(Duration::from_secs(10)),
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct Client {
    config: Config,
}

impl Client {
    #[must_use]
    pub const fn new(config: Config) -> Self {
        Self { config }
    }

    /// Check if the given email address exists
    /// and is setup to receive messages, without sending
    /// a message.
    pub async fn check(&self, address: &str) -> CheckResult {
        check_inner(address, &self.config).await.into()
    }
}

async fn check_inner(mail: &str, config: &Config) -> Result {
    let (local_part, domain) = mail.rsplit_once('@').ok_or(Error::InvalidAddressFormat)?;

    if local_part.is_empty() || domain.is_empty() {
        return Err(Error::InvalidAddressFormat);
    }

    let record = first_dns_record(domain).await?;
    let future = verify_mail(mail, &record);

    if let Some(timeout) = config.timeout {
        time::timeout(timeout, future)
            .await
            .map_err(|_| Error::Timeout)?
    } else {
        future.await
    }
}

/// Mail servers may respond with
///
/// - `4.1.8 Sender address rejected` (<https://www.suped.com/knowledge/email-deliverability/troubleshooting/what-does-smtp-bounce-reason-418-bad-senders-system-address-domain-of-sender-address-does-not-re>)
/// - `5.7.27 Sender address has null MX` (<https://www.rfc-editor.org/rfc/rfc7505#section-4.2>)
/// - SPF rejection as per <https://www.rfc-editor.org/rfc/rfc7208>
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

/// Get MX record with the highest preference
async fn first_dns_record(domain: &str) -> Result<MX> {
    lookup_mx(domain)
        .await?
        .first()
        .cloned()
        .ok_or(Error::NoMxRecords)
}

/// Get all usable MX records, sorted by preference.
/// Returns only non-root FQDN records.
async fn lookup_mx(domain: &str) -> Result<Vec<MX>> {
    let mut records: Vec<_> = hickory_resolver::Resolver::builder_tokio()?
        .build()
        .mx_lookup(domain)
        .await?
        .into_iter()
        // Only resolvable, fully-qualified domain names (FQDNs) are permitted when domain names are used in SMTP.
        // Source: https://datatracker.ietf.org/doc/html/rfc5321#section-2.3.5
        .filter(|r| r.exchange().is_fqdn())
        .filter(|r| !r.exchange().is_root()) // trying to connect "." will always fail
        .collect();

    records.sort_by_key(MX::preference);

    Ok(records)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::{CheckResult, Client, Config, FailureReason, UncertaintyReason};

    async fn check(address: &str) -> CheckResult {
        Client::default().check(address).await
    }

    #[tokio::test]
    async fn invalid_format() {
        let expected = CheckResult::Failure(FailureReason::InvalidAddressFormat);
        assert_eq!(check("some text").await, expected);
        assert_eq!(check("@").await, expected);
        assert_eq!(check("local-part@").await, expected);
        assert_eq!(check("@domain").await, expected);
    }

    #[tokio::test]
    async fn timeout() {
        let result = Client::new(Config {
            timeout: Some(Duration::ZERO),
        })
        .check("a@gmail.com")
        .await;

        assert_eq!(result, CheckResult::Uncertain(UncertaintyReason::Timeout))
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

        // this is intentionally considered `Uncertain`
        // 5.2.2 <thomas@icloud.com>: user is over quota
        assert!(matches!(
            check("thomas@icloud.com").await,
            CheckResult::Uncertain(UncertaintyReason::NegativeSmtpResponse(_))
        ));
    }

    #[tokio::test]
    async fn endler() {
        assert_eq!(check("matthias@endler.dev").await, CheckResult::Success);
        assert_eq!(
            check("idiomatic-rust-doesnt-exist-man@endler.dev").await,
            CheckResult::Failure(FailureReason::NoSuchAddress)
        );
    }

    #[tokio::test]
    async fn example() {
        assert_eq!(
            check("hello@example.com").await,
            CheckResult::Failure(FailureReason::NoMxRecords)
        );
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
        // TODO? These are addresses that shoud ideally be detected as invalid.
        // But it might be impossible if the services don't properly follow SMTP.
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
