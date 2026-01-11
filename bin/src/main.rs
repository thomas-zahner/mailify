//! mailify - identify if a mail address exists.
//! This is the binary executable of mailify.

#![warn(clippy::all, clippy::pedantic)]

use std::{env::args, process};

use mailify_lib::{CheckResult, Client};
use tokio::task;

#[tokio::main]
/// Exits with the following code:
///
/// - 0: None of the provided addresses could be determined to be erroneous
/// - 1: Incorrect usage of the program
/// - 2: At least one of the provided addresses is erroneous
async fn main() {
    let client = Client::default();
    let code = match args().collect::<Vec<_>>().as_slice() {
        [] => {
            eprintln!("You shouldn't be able to call programs without argv0");
            1
        }
        [argv0] => {
            eprintln!("Usage: {argv0} [email address]...");
            1
        }
        [_argv0, addresses @ ..] => check_all(addresses.to_vec(), client).await,
    };

    process::exit(code)
}

/// Check all addresses in parallel.
/// Return the program exit code.
async fn check_all(addresses: Vec<String>, client: Client) -> i32 {
    let tasks: Vec<_> = addresses
        .into_iter()
        .map(|address| {
            let client = client.clone();
            task::spawn(async move {
                let result = client.check(&address).await;
                println!("{address} - {result}");
                result
            })
        })
        .collect();

    let mut success = true;
    for task in tasks {
        let result = task.await.unwrap();
        if matches!(result, CheckResult::Failure(_)) {
            success = false;
        }
    }

    if success { 0 } else { 2 }
}
