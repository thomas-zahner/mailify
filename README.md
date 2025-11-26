Mailify - identify if a mail address exists.

# How does it work?

1. Minimalistic format validation
    1. Contains at least one `@`
    2. The local part (before last `@`) and the domain part (after last `@`) are not empty
2. Make a DNS [MX record](https://en.wikipedia.org/wiki/MX_record) lookup of the domain using [hickory-resolver](https://crates.io/crates/hickory-resolver)
3. Establish an [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) connection to the record with highest preference using [async-smtp](https://crates.io/crates/async-smtp)
4. Perform SMTP commands to send mail to specified address, quitting just before sending an actual mail.
