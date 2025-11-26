use std::sync::LazyLock;

use async_smtp::{
    EmailAddress, SmtpClient, SmtpTransport,
    commands::{MailCommand, RcptCommand},
    extension::ClientId,
};
use hickory_resolver::{ResolveError, proto::rr::rdata::MX};
use tokio::{io::BufStream, net::TcpStream};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidAddressFormat,
    DnsResolverError(String),
    SmtpError(String),
    IoError(String),
    NoMxRecords,
}

impl From<ResolveError> for Error {
    fn from(error: ResolveError) -> Self {
        Self::DnsResolverError(error.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::IoError(error.to_string())
    }
}

impl From<async_smtp::error::Error> for Error {
    fn from(error: async_smtp::error::Error) -> Self {
        Self::SmtpError(error.to_string())
    }
}

type Result<T = ()> = std::result::Result<T, Error>;

/// Check if the given email address exists
/// and is setup to receive messages, without sending
/// a message.
pub async fn check(mail: &str) -> Result {
    let (_local_part, domain) = mail.rsplit_once('@').ok_or(Error::InvalidAddressFormat)?;

    let records = dns_lookup(domain).await?;
    let record = records.first().ok_or(Error::NoMxRecords)?;

    verify_mail(mail, record).await
}

static SENDER_ADDRESS: LazyLock<EmailAddress> =
    LazyLock::new(|| EmailAddress::new("me@thomaszahner.ch".to_owned()).unwrap());

static CLIENT_ID: LazyLock<ClientId> = LazyLock::new(|| ClientId::Domain("mailify".into()));

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

async fn dns_lookup(domain: &str) -> Result<Vec<MX>> {
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
    use crate::Error;

    use super::check;

    #[tokio::test]
    async fn missing_at() {
        let result = check("some text").await;
        assert_eq!(result, Err(Error::InvalidAddressFormat));
    }

    #[tokio::test]
    async fn unknown_host() {
        let result = check("hi@unknownHost").await;
        assert!(
            matches!(result, Err(Error::DnsResolverError(e)) if e.contains("no records found"))
        );

        let result = check("hi@domainReallyDoesNotExist.org").await;
        assert!(
            matches!(result, Err(Error::DnsResolverError(e)) if e.contains("no records found"))
        );
    }

    #[tokio::test]
    async fn detects_my_domain_as_invalid() {
        assert!(matches!(
            check("me@thomaszahner.ch").await,
            Err(Error::SmtpError(_))
        ));
    }

    #[tokio::test]
    async fn gmail_positive() {
        assert_eq!(check("thomas.zahner@gmail.com").await, Ok(()));
    }

    #[tokio::test]
    async fn gmail_negative() {
        assert!(matches!(
            check("alice@gmail.com").await,
            Err(Error::SmtpError(_))
        ),);
    }

    #[tokio::test]
    async fn protonmail_positive() {
        assert_eq!(check("thomas.zahner@protonmail.ch").await, Ok(()));
    }

    #[tokio::test]
    async fn protonmail_negative() {
        let result = check("a@protonmail.ch").await;
        assert!(matches!(result, Err(Error::SmtpError(e)) if e.contains("Address does not exist")));
    }
}
