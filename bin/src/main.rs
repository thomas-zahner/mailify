//! mailify - identify if a mail address exists.
//! This is the binary executable of mailify.

#![warn(clippy::all, clippy::pedantic)]

use std::env::args;

use mailify_lib::check;
use tokio::task;

#[tokio::main]
async fn main() {
    match args().collect::<Vec<_>>().as_slice() {
        [argv0] => eprintln!("Usage: {argv0} [email address]..."),
        [_argv0, addresses @ ..] => check_all(addresses.to_vec()).await,
        [] => unreachable!("You shouldn't be able to call programs without argv0"),
    }
}

/// Check all addresses in parallel
async fn check_all(addresses: Vec<String>) {
    let tasks: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            task::spawn(async move {
                let result = check(&address).await;
                println!("{address} - {result}");
            })
        })
        .collect();

    for task in tasks {
        task.await.unwrap();
    }
}
