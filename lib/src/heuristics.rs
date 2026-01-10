use async_smtp::response::{Category, Detail, Response, Severity};

use crate::{CheckResult, FailureReason, UncertaintyReason};

/// Textual heuristics to detect blocklisting
const BLOCKLIST_WORDS: &[&str] = &[
    "blocklist",
    "blacklist",
    "greylist",
    "listing",
    "spam",
    "abuse",
    "blocked",
    "reputation",
    "sbrs", // Sender base reputation score: https://www.cisco.com/c/en/us/td/docs/security/ces/user_guide/esa_user_guide_12-5/b_ESA_Admin_Guide_ces_12_5/b_ESA_Admin_Guide_chapter_0101.pdf
    // Companies
    "proofpoint",
    "spamhaus",
    "abusix",
];

/// Inexistent mailbox per [RFC3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.2)
const MAILBOX_INEXISTENT_CODES: &[&str] = &["5.1.1", "5.1.2", "5.1.3", "5.1.6", "5.2.1"];

/// Textual heuristics for when RFC3463 doesn't suffice
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

/// Textual heuristics when reverse DNS entries are expected
const NO_REVERSE_HOSTNAME: &[&str] = &[
    // hi@gmx.de - Uncertain: Unclassified negative SMTP response: gmx.net (mxgmx108) Nemesis ESMTP Service not available No SMTP service Bad DNS PTR resource record. For explanation visit https://postmaster.gmx.net/en/case?c=r0601&i=ip
    "dns ptr",
    // "4.7.1 Client host rejected: cannot find your reverse hostname",
    "reverse hostname",
];

/// Handle transient and permanent error responses
pub(crate) fn from_erroneous(response: Response) -> CheckResult {
    use CheckResult::{Failure, Success, Uncertain};
    if blocklisted(&response) {
        Uncertain(UncertaintyReason::Blocklisted)
    } else if no_reverse_hostname_found(&response) {
        Uncertain(UncertaintyReason::NoReverseHostname)
    } else if no_such_address(&response) {
        Failure(FailureReason::NoSuchAddress)
    } else if exists(&response) {
        Success
    } else {
        Uncertain(UncertaintyReason::NegativeSmtpResponse(response))
    }
}

/// Whether a failure response indicates that the targeted mailbox exists
fn exists(response: &Response) -> bool {
    // Transient or permanent failure indicating that the mailbox exists
    // per [RFC3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.3):
    //
    // "X.2.0": The mailbox exists, but [...]
    // "X.2.1": Mailbox disabled, not accepting messages
    // "X.2.2": Mailbox full

    let code = response.code;
    matches!(
        code.severity,
        Severity::TransientNegativeCompletion | Severity::PermanentNegativeCompletion
    ) && code.category == Category::Connections
        && matches!(code.detail, Detail::Zero | Detail::One | Detail::Two)
}

fn no_reverse_hostname_found(response: &Response) -> bool {
    let message = &response.message;

    message_contains_word(message, NO_REVERSE_HOSTNAME)
        || no_reverse_hostname_found_outlook(message)
}

fn no_reverse_hostname_found_outlook(message: &[String]) -> bool {
    // Outlook/Hotmail error messages seems a bit generic.
    // https://www.suped.com/knowledge/email-deliverability/troubleshooting/what-causes-a-501-554-invalid-domain-name-error-when-sending-emails-to-office-365
    //
    // Example
    //
    // hi@hotmail.com - Uncertain: Unclassified negative SMTP response: 5.5.4 Invalid domain name [SN1PEPF0002636D.namprd02.prod.outlook.com 2026-01-10T14:19:01.912Z 08DE4E5F1EB66B10]
    message_contains_word(message, ["outlook.com"].as_slice()) // Hotmail & Outlook contain "outlook.com"
        && message_contains_word(message, ["invalid domain name"].as_slice())
}

fn blocklisted(response: &Response) -> bool {
    message_contains_word(&response.message, BLOCKLIST_WORDS)
}

fn no_such_address(response: &Response) -> bool {
    mailbox_unavailable(response) &&
    // rule out "no access, or command rejected for policy reasons"
    (
        // if the service follows RFC3463 and the code clearly indicates
        // the absence of the recipient address
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
