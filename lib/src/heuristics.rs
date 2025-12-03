use async_smtp::response::{Category, Detail, Response, Severity};

use crate::{CheckResult, FailureReason, UncertaintyReason};

const BLACKLIST_WORDS: &[&str] = &["listing", "spam", "block"];

/// Inexistent destination address per [RFC3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.2)
const BAD_MAILBOX_ADDRESS: &str = "5.1.1";
const BAD_SYSTEM_ADDRESS: &str = "5.1.2";
const BAD_SYSTEM_ADDRESS_SYNTAX: &str = "5.1.3";
const MAILBOX_MOVED: &str = "5.1.6";
const MAILBOX_DISABLED: &str = "5.2.1";

const NO_SUCH_ADDRESS_WORDS: &[&str] = &[
    // if the service follows RFC3463
    BAD_MAILBOX_ADDRESS,
    BAD_SYSTEM_ADDRESS,
    BAD_SYSTEM_ADDRESS_SYNTAX,
    MAILBOX_MOVED,
    MAILBOX_DISABLED,
    // otherwise fall back on textual heuristics
    "address does not exist",
    "no such user",
    "no such address",
    "user does not exist",
    "mailbox not found",
    "recipient address rejected",
    "account that you tried to reach does not exist",
    "double-checking the recipient",
];

/// Note: this handles permanent failures. (e.g. 5.2.1 and not transient 4.2.1)
pub(crate) fn handle_permanent(response: Response) -> CheckResult {
    use CheckResult::*;
    if blocklisted(&response) {
        Uncertain(UncertaintyReason::Blocklisted)
    } else if no_such_address(&response) {
        Failure(FailureReason::NoSuchAddress)
    } else {
        Uncertain(UncertaintyReason::NegativeSmtpResponse(response))
    }
}

fn blocklisted(response: &Response) -> bool {
    message_contains_word(&response.message, &BLACKLIST_WORDS)
}

fn no_such_address(response: &Response) -> bool {
    mailbox_unavailable(response) &&
    // rule out "no access, or command rejected for policy reasons"
    message_contains_word(&response.message, NO_SUCH_ADDRESS_WORDS)
}

/// [RFC5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.3):
/// 550  Requested action not taken: mailbox unavailable (e.g., mailbox
/// not found, no access, or command rejected for policy reasons)
fn mailbox_unavailable(response: &Response) -> bool {
    let mailbox_unavailable = response.code.severity == Severity::PermanentNegativeCompletion
        && response.code.category == Category::MailSystem
        && response.code.detail == Detail::Zero;
    mailbox_unavailable
}

fn message_contains_word(message: &Vec<String>, words: &[&str]) -> bool {
    message
        .iter()
        .map(|line| line.to_lowercase())
        .any(|line| words.iter().any(|word| line.contains(word)))
}
