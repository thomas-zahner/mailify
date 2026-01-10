use futures::{SinkExt, StreamExt};
use std::collections::VecDeque;
use std::net::SocketAddr;
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::{Framed, LinesCodec};

async fn listen<R: Into<RequestResponseList>>(list: R) {
    let addr = SocketAddr::from(([127, 0, 0, 1], 2525));
    let listener = TcpListener::bind(addr).await.unwrap();

    match listener.accept().await {
        Ok((stream, _)) => handle_connection(stream, list.into()).await,
        Err(err) => panic!("Error establishing SMTP connection: {:?}", err),
    }
}

async fn handle_connection(mut stream: TcpStream, list: RequestResponseList) {
    let (_, writer) = stream.split();
    let mut writer = BufWriter::new(writer);

    writer.write_all(b"220 SMTP server mock\r\n").await.unwrap();
    writer.flush().await.unwrap();

    handle_session(stream, list).await;
}

async fn handle_session(stream: TcpStream, mut list: RequestResponseList) {
    let mut framed = Framed::new(stream, LinesCodec::new());
    while let Some(line_str) = framed.next().await {
        let line = line_str.unwrap();
        let response = list.get_next(line);
        send_commands(&mut framed, vec![response]).await;
    }
}
async fn send_commands(framed: &mut Framed<TcpStream, LinesCodec>, commands: Vec<String>) {
    // only need to add \r because the codec only adds \n
    let messages = futures::stream::iter(commands.into_iter().map(|x| format!("{}\r", x)));
    framed.send_all(&mut messages.map(Ok)).await.unwrap();
}

struct RequestResponseList(VecDeque<RequestResponse>);

impl From<&[(&str, &str)]> for RequestResponseList {
    fn from(value: &[(&str, &str)]) -> Self {
        Self(value.iter().cloned().map(RequestResponse::from).collect())
    }
}

impl RequestResponseList {
    fn get_next(&mut self, actual: String) -> String {
        let Some(expected) = self.0.pop_front() else {
            panic!("Expected no more requests but received '{actual}'");
        };

        if expected.request != actual {
            panic!("Expected request '{}' but got '{actual}'", expected.request,);
        }

        expected.response
    }
}

struct RequestResponse {
    request: String,
    response: String,
}

impl From<(&str, &str)> for RequestResponse {
    fn from((request, response): (&str, &str)) -> Self {
        Self {
            request: request.to_string(),
            response: response.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serial_test::serial;
    use std::time::Duration;

    use tokio::{task, time::sleep};

    use crate::listen;
    use mailify_lib::{CheckResult, Client, Config};

    /// Default template for expected requets
    /// with their associated response
    macro_rules! default_template {
        ($final_message:expr) => {
            [
                ("EHLO [127.0.0.1]", "250 OK"),
                ("EHLO example.com.", "250 OK"),
                ("MAIL FROM:<me@thomaszahner.ch>", "250 OK"),
                $final_message,
            ]
            .as_slice()
        };
    }

    async fn check(address: &str) -> CheckResult {
        Client::new(Config {
            port: 2525,
            ..Default::default()
        })
        .check(address)
        .await
    }

    #[serial]
    #[tokio::test]
    async fn success() {
        let server = task::spawn(async move {
            listen(default_template!(("RCPT TO:<hello@[127.0.0.1]>", "250 OK"))).await;
        });

        sleep(Duration::from_millis(100)).await;
        assert_eq!(check("hello@[127.0.0.1]").await, CheckResult::Success);
        server.await.unwrap();
    }

    #[serial]
    #[tokio::test]
    async fn no_such_address() {
        let server = task::spawn(async move {
            listen(default_template!((
                "RCPT TO:<hello@[127.0.0.1]>",
                "550 No such user"
            )))
            .await;
        });

        sleep(Duration::from_millis(100)).await;
        assert_eq!(
            check("hello@[127.0.0.1]").await,
            CheckResult::Failure(mailify_lib::FailureReason::NoSuchAddress)
        );
        server.await.unwrap();
    }
}
