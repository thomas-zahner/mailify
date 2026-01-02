use async_smtp::response::{Category, Detail, Response, Severity};

use crate::{CheckResult, FailureReason, UncertaintyReason};

const BLACKLIST_WORDS: &[&str] = &["listing", "spam", "block"];

/// Inexistent mailbox per [RFC3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.2)
const MAILBOX_INEXISTENT_CODES: &[&str] = &["5.1.1", "5.1.2", "5.1.3", "5.1.6", "5.2.1"];

/// Transient or permanent failure indicating that the mailbox exists
/// per [RFC3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.2).
const MAILBOX_EXISTENT_CODES: &[&str] = &[
    "4.2.0", "4.2.1", "4.2.2", // transient
    "5.2.0", "5.2.1", "5.2.2", // permanent
];

const NO_SUCH_ADDRESS_WORDS: &[&str] = &[
    "address does not exist",
    "no such user",
    "no such address",
    "user does not exist",
    "user unknown",
    "mailbox not found",
    "recipient address rejected",
    "account that you tried to reach does not exist",
    "double-checking the recipient",
];

pub(crate) fn handle(response: Response) -> CheckResult {
    use CheckResult::{Failure, Success, Uncertain};
    if blocklisted(&response) {
        Uncertain(UncertaintyReason::Blocklisted)
    } else if no_such_address(&response) {
        Failure(FailureReason::NoSuchAddress)
    } else if exists(&response) {
        Success
    } else {
        Uncertain(UncertaintyReason::NegativeSmtpResponse(response))
    }
}

/// A failure response that indicates that the targeted mailbox exists
fn exists(response: &Response) -> bool {
    message_contains_word(&response.message, MAILBOX_EXISTENT_CODES)
}

fn blocklisted(response: &Response) -> bool {
    message_contains_word(&response.message, BLACKLIST_WORDS)
}

fn no_such_address(response: &Response) -> bool {
    mailbox_unavailable(response) &&
    // rule out "no access, or command rejected for policy reasons"
    (
        // if the service follows RFC3463
        message_contains_word(&response.message, MAILBOX_INEXISTENT_CODES) ||
        // otherwise fall back on textual heuristics
        message_contains_word(&response.message, NO_SUCH_ADDRESS_WORDS)
    )
}

/// [RFC5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.3):
/// 550  Requested action not taken: mailbox unavailable (e.g., mailbox
/// not found, no access, or command rejected for policy reasons)
fn mailbox_unavailable(response: &Response) -> bool {
    response.code.severity == Severity::PermanentNegativeCompletion
        && response.code.category == Category::MailSystem
        && response.code.detail == Detail::Zero
}

fn message_contains_word(message: &[String], words: &[&str]) -> bool {
    message
        .iter()
        .map(|line| line.to_lowercase())
        .any(|line| words.iter().any(|word| line.contains(word)))
}
