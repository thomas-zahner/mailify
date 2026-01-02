mailify - identify if a mail address exists.

# How does it work?

1. Minimalistic format validation
    1. Contains at least one `@`
    2. The local part (before last `@`) and the domain part (after last `@`) are not empty
2. Make a DNS [MX record](https://en.wikipedia.org/wiki/MX_record) lookup of the domain using [hickory-resolver](https://crates.io/crates/hickory-resolver)
3. Establish an [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) connection to the record with highest preference using [async-smtp](https://crates.io/crates/async-smtp)
4. Perform SMTP commands to send mail to specified address, quitting just before sending an actual mail.

# State of SMTP

There is `550` and `5.1.1` for "mailbox unavailable" we can use to detect if an address exists.
`550` is defined in [RFC 5321](https://www.rfc-editor.org/rfc/rfc5321.html#section-4.2.3),
`5.1.1` is defined in [RFC 3463](https://www.rfc-editor.org/rfc/rfc3463#section-3.2).

TODO: in practice RFC 3463 is not always followed

## Port filtering

As per [Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#Ports):

> Many ISPs now block all outgoing port 25 traffic from their customers.
> Mainly as an anti-spam measure, but also to cure for the higher cost they have when leaving it open, perhaps by charging more from the few customers that require it open.

Also see <https://web.archive.org/web/20150828005734/http://www.pcworld.com/article/116843/article.html>.
In practice it means if you are unlucky and use the "wrong" ISP,
mailify will timeout on checking and will report `CheckResult::Uncertain(UncertaintyReason::Timeout)`.

## Blocklisting

TODO.
