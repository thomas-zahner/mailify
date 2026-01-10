mailify - identify if a mail address exists.

# How does it work?

1. Minimalistic format validation
    1. Contains at least one `@`
    2. The local part (before last `@`) and the domain part (after last `@`) are not empty
2. If the domain part is not a domain literal (e.g. `me@[1.1.1.1]`) make a DNS [MX record](https://en.wikipedia.org/wiki/MX_record) lookup [hickory-resolver](https://crates.io/crates/hickory-resolver) to get the record with highest preference
3. Establish an [SMTP](https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol) connection to the previously extracted IP using [async-smtp](https://crates.io/crates/async-smtp)
4. Perform SMTP commands to send mail to the specified address, quitting just before sending an actual mail.

# Goals

Identify if a given mail address exists or not.
In case of errors, classify the errors as best as we can for good usability.
Document how these errors could be resolved by users.

# Non-goals

We don't implement quirky workarounds if identification fails with SMTP.
Check out [check-if-email-exists](https://github.com/reacherhq/check-if-email-exists)
if you are looking for such workarounds.

# State of SMTP

Figuring out if a given address exists with SMTP is rather straight forward.
Unfortunately, in the real world there are deterrents which can prevent us to do so,
such as port filtering by ISPs and blocklisting by mail servers.
This means that if you are using the "wrong" ISP or if your IP address is
not considered "trustworthy" enough by the mail server,
you will be prevented from obtaining any useful information.

These mechanisms evolved historically to prevent spam.
Whether these measures are adequate and justify sacrificing
the capabilities and usefulness of a protocol might be debatable.

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
In SMTP land, if you are blocklisted the ban is usually permanent.
If you are lucky, you might be offered a link to request an unban from the blocklising service.

## Reverse DNS lookup

Some SMTP servers perform a
[reverse DNS lookup](https://en.wikipedia.org/wiki/Reverse_DNS_lookup#Records_other_than_PTR_records)
for the IP address used to connect to their server and reject requests if no
[PTR record](https://en.wikipedia.org/wiki/List_of_DNS_record_types#PTR)
can be found.
In that case we can obtain no useful information, unless
you create such a DNS record for your IP address.

## Lying SMTP servers

Here is a list of known providers which "lie" about the existence of mail boxes.
They might do this to prevent their users from being discovered.

- yahoo.com
- aol.com
- ... (probably much more, feel free to open up a PR)

In practice this means that mailify will report a false positive.
Contrary to the above issues troubleshooting might be of no use in this case.

# Troubleshooting

mailify is only using SMTP for email identification.
There are currently no plans to change this behaviour as we like to
keep mailify simple and stable.

If your results are unsatisfactory due to problems mentioned above,
you can try to run mailify on a different computer or connect
to a different network. (physically or via VPN)

Ideally the network has:

1. an ISP which doesn't block/filter port 25
2. a public static IP address
3. a "trustworthy" public IP address
4. a reverse DNS PTR record set up for its IP address
