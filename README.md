Mailify - identify if a mail address exists.

1. check format? (https://www.netmeister.org/blog/email.html)
2. domain (after @) is reachable
3. domain has MX records
4. mail servers referenced in MX records accept SMTP connection (see <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol#SMTP_transport_example>)
    1. Try ports 25, 587, 465, 2525 over TCP
    2. nc -v smtp.example.com 25
5. Do all steps before sending mail. Use [return codes](https://en.wikipedia.org/wiki/List_of_SMTP_server_return_codes) to detect errors.
    1. HELO
    2. MAIL FROM (maybe optional? and beware of SPF check)
    3. RCPT TO
    4. DATA (probably not necessary?)

TODO: Use VRFY instead?


# Examples

```
➜ dig gmail.com MX +short
20 alt2.gmail-smtp-in.l.google.com.
40 alt4.gmail-smtp-in.l.google.com.
10 alt1.gmail-smtp-in.l.google.com.
5 gmail-smtp-in.l.google.com.
30 alt3.gmail-smtp-in.l.google.com.
➜ nc -v alt1.gmail-smtp-in.l.google.com 25
Connection to alt1.gmail-smtp-in.l.google.com (2a00:1450:4025:c01::1a) 25 port [tcp/smtp] succeeded!
220 mx.google.com ESMTP a640c23a62f3a-b7655051695si585919666b.873 - gsmtp
HELO out.wikipedia.org
250 mx.google.com at your service
MAIL FROM:<bob@example.org>
250 2.1.0 OK a640c23a62f3a-b7655051695si585919666b.873 - gsmtp
RCPT TO:<alice@gmail.com>
550-5.1.1 The email account that you tried to reach does not exist. Please try
550-5.1.1 double-checking the recipient's email address for typos or
550-5.1.1 unnecessary spaces. For more information, go to
550 5.1.1  https://support.google.com/mail/?p=NoSuchUser a640c23a62f3a-b7655051695si585919666b.873 - gsmtp
```


```
➜ nc -v mx1.mail.hostpoint.ch 25
Connection to mx1.mail.hostpoint.ch (2a00:d70:0:e::200) 25 port [tcp/smtp] succeeded!
220 mxin019.mail.hostpoint.ch ESMTP Exim 4.98.2 Mon, 24 Nov 2025 15:05:30 +0100
HELO out.wikipedia.org
250 mxin019.mail.hostpoint.ch Hello out.wikipedia.org [2a02:21b4:9e59:7b00:d38d:2898:55b2:f2ef]
MAIL FROM:<bob@example.org>
550-SPF check failed: 2a02:21b4:9e59:7b00:d38d:2898:55b2:f2ef is not allowed to
550 send mail from example.org
MAIL FROM:<bob@example.com>
550-SPF check failed: 2a02:21b4:9e59:7b00:d38d:2898:55b2:f2ef is not allowed to
550 send mail from example.com
MAIL FROM:<bob@lol3doijwc.org>
250 OK
RCPT TO:<alice@gmail.com>
550 no such address here (MX do not point to us)
RCPT TO:<alice@thomaszahner.ch>
550 no such address here
```
