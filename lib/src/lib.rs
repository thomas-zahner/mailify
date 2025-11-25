use std::{
    io::{BufRead, BufReader, Write},
    net::TcpStream,
    str::FromStr,
    time::Duration,
};

use hickory_resolver::{ResolveError, proto::rr::rdata::MX};

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidFormat,
    DnsResolverError(String),
    IoError(String),
    NoMxRecords,
    InvalidSmtpReply,
    NegativeSmtpReply,
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

type Result<T = ()> = std::result::Result<T, Error>;

/// Check if the given email address exists
/// and is setup to receive messages, without sending
/// a message.
pub async fn check(mail: &str) -> Result {
    let (_local_part, domain) = mail.rsplit_once('@').ok_or(Error::InvalidFormat)?;

    let records = dns_lookup(domain).await?;

    let record = records.first().ok_or(Error::NoMxRecords)?;
    verify_mail(mail, record)
}

fn verify_mail(mail: &str, record: &MX) -> Result {
    const PORT: u16 = 25;
    const READ_WRITE_TIMEOUT: Duration = Duration::from_secs(1);
    const SENDER_ADDRESS: &str = "me@thomaszahner.ch";

    let host = record.exchange();
    let mut stream = TcpStream::connect(format!("{host}:{PORT}"))?;
    stream.set_read_timeout(Some(READ_WRITE_TIMEOUT))?;

    let mut reader = BufReader::new(stream.try_clone()?);

    verify_positive_response(&mut reader)?;

    // https://www.rfc-editor.org/rfc/rfc5321.html#section-4.1.1.1
    stream.write("HELO a\r\n".as_bytes())?;
    verify_positive_response(&mut reader)?;

    stream.write(format!("MAIL FROM:<{SENDER_ADDRESS}>\r\n").as_bytes())?;
    verify_positive_response(&mut reader)?;

    stream.write(format!("RCPT TO:<{mail}>\r\n").as_bytes())?;
    verify_positive_response(&mut reader)?;

    stream.write("QUIT\r\n".as_bytes())?;
    verify_positive_response(&mut reader)?;

    Ok(())
}

fn verify_positive_response(reader: &mut BufReader<TcpStream>) -> Result {
    match read_response(reader)?.is_positive() {
        true => Ok(()),
        false => Err(Error::NegativeSmtpReply),
    }
}

fn read_response(reader: &mut BufReader<TcpStream>) -> Result<SmtpReplyCode> {
    let mut line = String::new();
    reader.read_line(&mut line)?;

    let (code, rest) = line.split_once(" ").ok_or(Error::InvalidSmtpReply)?;
    dbg!(rest);
    Ok(code.parse()?)
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

/// https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.1
#[derive(Debug)]
struct SmtpReplyCode(u16);

impl SmtpReplyCode {
    fn is_positive(&self) -> bool {
        self.0 >= 200 && self.0 < 400
    }
}

impl FromStr for SmtpReplyCode {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(SmtpReplyCode(
            s.parse().map_err(|_| Error::InvalidSmtpReply)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::Error;

    use super::check;

    #[tokio::test]
    async fn missing_at() {
        let result = check("some text").await;
        assert_eq!(result, Err(Error::InvalidFormat));
    }

    #[tokio::test]
    async fn detects_my_domain_as_invalid() {
        assert_eq!(
            check("me@thomaszahner.ch").await,
            Err(Error::NegativeSmtpReply)
        );
    }

    #[tokio::test]
    async fn gmail_positive() {
        assert_eq!(check("thomas.zahner@gmail.com").await, Ok(()));
    }

    #[tokio::test]
    async fn gmail_negative() {
        // TODO: fix me
        assert_eq!(
            check("l1o89oc92fl134x7@gmail.com").await,
            Err(Error::NegativeSmtpReply)
        );
    }
}
