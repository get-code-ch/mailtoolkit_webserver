# mailtoolkit_webserver

Mail analysis service built on [mailtoolkit](https://github.com/get-code-ch/mailtoolkit).

The server is the MX of a domain. A visitor clicks « Nouvelle analyse » and gets a random address
(`k7f3q9x2m4@example.com`) and a private page. They forward the suspect mail **as an attachment** to that
address; the attached mail (not the forwarding one) is displayed on the private page without running any of
its code.

The SMTP server uses the Go standard library only; HTML parsing relies on `golang.org/x/net/html` (the
tokenizer browsers follow) and `golang.org/x/net/idna`. Requires Go 1.26 or later.

## How it works

- **SMTP** on three ports, sharing the same rules: only the active random addresses of the configured
  domains are accepted (`550` otherwise), so the server is never an open relay.

  | Port | Mode |
  |------|------|
  | 25   | MX, STARTTLS offered |
  | 587  | submission, STARTTLS required before `MAIL` |
  | 465  | implicit TLS |

- **Extraction**: `message/rfc822` parts and `.eml` / `.msg` files attached to the received mail are kept byte
  for byte (needed to verify their signatures).
- **Upload**: a `.eml` or Outlook `.msg` file can also be uploaded from the home page (new mailbox) or from a
  mailbox page; the file is recognized from its content, whatever its name.
- **Outlook .msg** (package `msg`, on top of `cfb`): properties, recipients, attachments, embedded messages,
  8-bit strings in their codepage, compressed RTF (LZFu) with the HTML it encapsulates. The message is
  converted to an RFC 5322 mail for the analysis, keeping the original internet headers when Outlook saved
  them; its body being rebuilt, DKIM signatures cannot verify, which the page explains.
- **Privacy**: the page link contains a 128-bit secret token, distinct from the address. Mailboxes and mails
  are deleted after the retention delay (24 h by default).
- **Display**: mail contents are shown in a sandboxed iframe with a `Content-Security-Policy: sandbox` header:
  no script runs and no remote image (tracking pixel) is loaded. Attachments are always downloaded, never
  displayed.
- **Links panel**: every URL of the mail (links, images, forms, CSS, redirections, URLs written in the text)
  is listed next to the content, never clickable, with alerts: displayed text pointing to another domain,
  `javascript:` / `data:` schemes, `user@` before the domain, IP addresses, unusual ports, URL shorteners,
  internationalized domains (homographs), forms, automatic redirections, tracking pixels, and the final
  destination of redirectors such as Outlook Safe Links.
- **Header analysis** (package `mailauth`, standard library plus `golang.org/x/net/publicsuffix`):
  - DKIM signatures verified (RSA, Ed25519, simple/relaxed canonicalization; `rsa-sha1` and keys shorter than
    1024 bits refused, `l=` flagged); the attached mail is kept byte for byte for that purpose;
  - SPF recomputed with the IP of the server that sent the mail, guessed from the `Received` headers (the user
    can pick another hop), with the RFC 7208 limits and macros;
  - DMARC policy and alignment of SPF and DKIM with the From domain;
  - results written by the receiving servers (`Authentication-Results`, `ARC-Authentication-Results`,
    `Received-SPF`), the `Received` path, and inconsistencies: address in the display name, Reply-To or
    Return-Path on another domain, missing Message-ID, date far from the reception.

  The checks run when the analysis page is first opened, with the current DNS records: a key rotated since
  the mail was sent makes its DKIM signature fail.
- **Attachments analysis** (package `filecheck`), without opening the files: real type from the content
  compared with the name, MD5/SHA-1/SHA-256 (with a VirusTotal search by hash), and alerts for executables,
  shortcuts, disk images, dangerous extensions, double extensions and right-to-left override characters,
  VBA macros and Excel 4.0 (XLM) macro sheets, embedded OLE objects, ActiveX, remote templates and other
  external relationships, DDE fields, password protected documents and archives, ZIP content, PDF actions
  (JavaScript, OpenAction, Launch, embedded files), RTF objects (Equation.3), HTML and SVG scripts, forms and
  HTML smuggling. Office 97-2003 files are read with the `cfb` package, a defensive compound file reader.

## Configuration

`./conf/configuration.json`, or the file given with `-config`:

| Field              | Description |
|--------------------|-------------|
| `hostname`         | MX host name, used in the SMTP banner and `Received` headers |
| `domains`          | accepted domains, the first one is used for new addresses |
| `server`           | listening IP address, empty for all |
| `smtp_ports`       | `mx`, `submission` and `smtps` ports, empty to disable one |
| `http_port`        | HTTP port; redirects to HTTPS and serves ACME challenges when HTTPS is enabled |
| `https_port`       | HTTPS port |
| `cert`, `key`      | certificate files for HTTPS, STARTTLS and the submission ports, reloaded when they change |
| `acme_webroot`     | folder served under `/.well-known/acme-challenge/` for `certbot --webroot` |
| `data_folder`      | where the mailboxes are stored |
| `retention`        | mailbox lifetime, e.g. `"24h"` |
| `max_message_size` | in bytes, 25 MB by default |
| `max_mailboxes`    | maximum number of active mailboxes |
| `ingest_token`     | enables `POST /ingest` (see below); overridden by the `MTK_INGEST_TOKEN` environment variable |
| `behind_cloudflare`| trust the visitor address given by the Cloudflare proxies |

Without `cert` and `key`, only the MX port (without STARTTLS) and plain HTTP are started.

## Deployment

1. DNS, for the domain `example.com` served by the host `mx.example.com`:

   ```
   mx.example.com.  A    203.0.113.10
   example.com.     MX   10 mx.example.com.
   ```

2. Open the incoming ports 25, 465, 587, 80 and 443.

3. Get a certificate covering `mx.example.com` (and the web site name), for example:

   ```sh
   certbot certonly --webroot -w ./acme -d mx.example.com
   ```

   The server must be running (port 80) for the webroot challenge. Renewals are picked up without restart.

4. Run it:

   ```sh
   docker build -t mailtoolkit_webserver .
   docker run -d --name mail-analyzer \
     -p 25:25 -p 465:465 -p 587:587 -p 80:80 -p 443:443 \
     -v "$PWD/conf:/app/conf:ro" \
     -v /etc/letsencrypt:/etc/letsencrypt:ro \
     -v "$PWD/acme:/app/acme" \
     -v mail-analyzer-data:/app/data \
     mailtoolkit_webserver
   ```

   with `"cert": "/etc/letsencrypt/live/mx.example.com/fullchain.pem"` and
   `"key": "/etc/letsencrypt/live/mx.example.com/privkey.pem"` in the configuration.

## Behind Cloudflare, without port 25

Mail servers deliver to the MX on port 25 only. When the host blocks it, Cloudflare Email Routing can receive
the mails and an Email Worker forwards them to the server over HTTPS (`POST /ingest`):

1. Generate a secret and give it to the server, never in a committed file:

   ```sh
   export MTK_INGEST_TOKEN=$(openssl rand -hex 32)
   ```

2. In Cloudflare, enable **Email Routing** for the domain of the addresses (it publishes its own MX records).
3. Create a Worker with `cloudflare/email-worker.js`, a variable `INGEST_URL`
   (`https://<host>/ingest`) and a secret `INGEST_TOKEN` (the same value).
4. Add a **catch-all** routing rule with the action *Send to a Worker*.

Unknown or expired addresses are rejected (the server answers 404 and the Worker rejects the mail); the other
errors are temporary. Set `"behind_cloudflare": true` so that the rate limits use the visitor address given by
Cloudflare (`CF-Connecting-IP`, trusted only from the Cloudflare address ranges).

With the Cloudflare proxy, a self-signed certificate is enough for the origin with the SSL/TLS mode **Full**
(or use a Cloudflare Origin CA certificate for **Full (strict)**):

```sh
mkdir -p ssl && openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=<host>" \
  -addext "subjectAltName=DNS:<host>" -keyout ssl/server.key -out ssl/server.crt
```

## Development

Use non privileged ports (`2525`, `2587`, `2465`, `8080`, `8443`) and a self-signed certificate:

```sh
mkdir -p ssl
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -keyout ssl/server.key -out ssl/server.crt
go run . -config conf/dev.json
```

Create a mailbox on `https://localhost:8443`, then send a mail with an attached `.eml`:

```sh
curl smtp://localhost:2525 --mail-from me@example.org --mail-rcpt <address> -T carrier.eml
```

`carrier.eml` must use CRLF line endings: curl only escapes the lines starting with a dot after a CRLF.

To work on mailtoolkit at the same time, create a `go.work` file in the parent folder:

```sh
go work init ./mailtoolkit ./mailtoolkit_webserver
```
