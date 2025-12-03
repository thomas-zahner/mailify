use std::env::args;

use mailify::check;

#[tokio::main]
async fn main() {
    match args().collect::<Vec<_>>().as_slice() {
        [argv0] => eprintln!("Usage: {argv0} [email address]..."),
        [_argv0, addresses @ ..] => {
            for address in addresses {
                println!("{:?}", check(address).await);
            }
        }
        [] => unreachable!("You shouldn't be able to call programs without argv0"),
    }
}
