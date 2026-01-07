//! mailify - identify if a mail address exists.
//! This is the binary executable of mailify.

#![warn(clippy::all, clippy::pedantic)]

use std::env::args;

use mailify_lib::Client;
use tokio::task;

#[tokio::main]
async fn main() {
    let client = Client::default();
    match args().collect::<Vec<_>>().as_slice() {
        [argv0] => eprintln!("Usage: {argv0} [email address]..."),
        [_argv0, addresses @ ..] => check_all(addresses.to_vec(), client).await,
        [] => unreachable!("You shouldn't be able to call programs without argv0"),
    }
}

/// Check all addresses in parallel
async fn check_all(addresses: Vec<String>, client: Client) {
    let tasks: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            let client = client.clone();
            task::spawn(async move {
                let result = client.check(&address).await;
                println!("{address} - {result}");
            })
        })
        .collect();

    for task in tasks {
        task.await.unwrap();
    }
}
