mailify - identify if a mail address exists.

# How does it work?

1. Minimalistic format validation
    1. Contains at least one `@`
    2. The local part (before last `@`) and the domain part (after last `@`) are not empty
2. Make a DNS [MX record](https://en.wikipedia.org/wiki/MX_record) lookup of the domain using [hickory-resolver](https://crates.io/crates/hickory-resolver)
3. Establish an [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) connection to the record with highest preference using [async-smtp](https://crates.io/crates/async-smtp)
4. Perform SMTP commands to send mail to specified address, quitting just before sending an actual mail.

# State of SMTP

Figuring out if a given address exists with SMTP is rather straight forward.
Unfortunately, in the real world there are two main deterrents which can prevent us to do so:
port filtering by ISPs and blocklisting by mail servers.
This means that if you are using the "wrong" ISP or if your IP address is
not considered "trustworthy" enough by the mail server,
you will be prevented from obtaining any useful information.

These two mechanisms exist to prevent spam.
Whether it is justified to severely limit the capabilities and usefulness of a protocol is debatable.

mailify does not propose a solution to circumvent these problems.
However, mailify aims to be accurate even if you are affected by these deterrents.
This is achieved by introducing the variant `Uncertain` to `CheckResult`.
So for example if you are blocklisted mailify will not return `Success` or `Failure`,
but `Uncertain`.

## Port filtering

As per [Wikipedia](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#Ports):

> Many ISPs now block all outgoing port 25 traffic from their customers.
> Mainly as an anti-spam measure, but also to cure for the higher cost they have when leaving it open, perhaps by charging more from the few customers that require it open.

Also see <https://web.archive.org/web/20150828005734/http://www.pcworld.com/article/116843/article.html>.
In practice it means if you are unlucky and use the "wrong" ISP,
mailify will timeout on checking and will report `CheckResult::Uncertain(UncertaintyReason::Timeout)`.

## Blocklisting

If your ISP doesn't filter or block your connection to mail servers,
you might still be blocked by the mail server itself.
Mail servers might block you based on your IP address or other metrics.
There are companies which offer blocklist software such as [abusix](https://abusix.com/)
and [Spamhaus](https://www.spamhaus.org/blocklists/).
This is somewhat comparable to the Cloudflare for HTTP.
However, Cloudflare rarely bans access to a website and if it does,
there is mostly a possibility to solve a CAPTCHA challenge to disable the ban.
In SMTP land, if you are blocklisted the ban is often permanent.
If you are lucky, you might be offered a link to request an unban from the blocklising service.
