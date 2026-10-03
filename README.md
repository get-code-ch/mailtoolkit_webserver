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
  is listed next to the content, grouped by domain in folding sections (the suspect ones open), never
  clickable, with alerts: displayed text pointing to another domain,
  `javascript:` / `data:` schemes, `user@` before the domain, IP addresses, unusual ports, URL shorteners,
  internationalized domains (homographs), forms, automatic redirections, tracking pixels, and the final
  destination of redirectors such as Outlook Safe Links.
- **Header analysis** (package `mailauth`, standard library plus `golang.org/x/net/publicsuffix`):
  - DKIM signatures verified (RSA, Ed25519, simple/relaxed canonicalization; `rsa-sha1` and keys shorter than
    1024 bits refused, `l=` flagged); the attached mail is kept byte for byte for that purpose. For each
    signature, the page shows whether the body hash matches and every field named in `h=`: its value in the
    mail next to the exact text hashed after canonicalization (absent fields, signed to prevent their
    addition, included), then the DKIM-Signature field hashed last;
  - SPF recomputed with the IP of the server that sent the mail, guessed from the `Received` headers (the user
    can pick another hop), with the RFC 7208 limits and macros;
  - DMARC policy and alignment of SPF and DKIM with the From domain;
  - results written by the receiving servers (`Authentication-Results`, `ARC-Authentication-Results`,
    `Received-SPF`), the `Received` path, and inconsistencies: address in the display name, Reply-To or
    Return-Path on another domain, missing Message-ID, date far from the reception;
  - ARC chain (RFC 8617) validated: seals and newest message signature; the results recorded by a first sealer that
    is a receiving provider are used when forwarding broke DKIM;
  - verdicts of the antispam filters the mail went through, decoded: Microsoft 365 / Exchange Online
    Protection (SCL, BCL, SFV, CAT, delivery folder…), SpamAssassin and Rspamd (score, threshold, rules sorted
    by weight), Proofpoint, Gmail (`X-Gm-Spam`, `X-Gm-Phishy`), Barracuda, Mimecast, and the other filtering
    fields as they are; only the fields added by a receiving server are trusted (the sender can forge them),
    the worst trusted verdict is shown in the summary;
  - all the header fields sorted by category (sender and recipients, authentication, path, content, lists,
    antispam filtering, provider extensions), with RFC 2047 values decoded, DKIM, ARC, `Authentication-Results` and
    `Content-Type` parameters split, and a badge on each field covered by a DKIM signature; the raw source
    stays available.

  The result shown for SPF, DKIM and DMARC is first the one written by the receiving provider
  (`Authentication-Results` of a server that received the mail: Proton Mail, Google, Microsoft 365…; results
  added by the sender are displayed but not trusted). The internal verification runs on the mail as forwarded
  or exported, which providers often rebuild: when it fails, a warning asks for caution instead of an error.
  The internal checks use the current DNS records: a key rotated since the mail was sent makes its DKIM
  signature fail.
- **Attachments analysis** (package `filecheck`), without opening the files: real type from the content
  compared with the name, MD5/SHA-1/SHA-256 (with a VirusTotal search by hash), and alerts for executables,
  shortcuts, disk images, dangerous extensions, double extensions and right-to-left override characters,
  VBA macros and Excel 4.0 (XLM) macro sheets, embedded OLE objects, ActiveX, remote templates and other
  external relationships, DDE fields, password protected documents and archives, ZIP content, PDF actions
  (JavaScript, OpenAction, Launch, embedded files), RTF objects (Equation.3), HTML and SVG scripts, forms and
  HTML smuggling. Office 97-2003 files are read with the `cfb` package, a defensive compound file reader.
- **S/MIME signature** (package `smime`, standard library plus `golang.org/x/crypto/ocsp`): CMS reader (BER
  included), integrity of the signed content, signature (RSA, RSA-PSS, ECDSA, Ed25519), certificate chain to the
  system certification authorities at the signing time, revocation through OCSP then the CRL, certified address
  compared with the sender, and identity level of the certificate (CA/Browser Forum S/MIME policies: mailbox,
  organization, sponsor, individual). A valid signature for the sender proves who sent the mail even when DKIM
  was broken by a forward or an export; encrypted messages are reported as such.
- **Reputation**: DNS blocklists (Spamhaus ZEN and DBL, SpamCop, SURBL by default) for the sending server and the
  domains of the mail, registration date of these domains (RDAP), and lookalike domains of often impersonated
  brands (PayPal, Microsoft, PostFinance, TWINT, Swisscom…): letters swapped or replaced by lookalike characters,
  brand name in another domain.
- **Risk assessment**: every finding gets a weight and a plain-language explanation; one serious finding or a total
  of 5 turns the light red, a total of 2 orange. The analysis page opens on a **simplified view** for non-technical
  visitors: a traffic light, what is doubtful, what is reassuring and what to do. A switch next to the theme one
  shows the detailed analysis, and the choice is remembered.

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
| `reputation`       | external reputation checks, see below |
| `trusted_domains`  | sender domains (subdomains included) whose authenticated mails are not flagged for their links, see below |

Without `cert` and `key`, only the MX port (without STARTTLS) and plain HTTP are started.

### Trusted domains

Mailing platforms (Dynamics 365, Salesforce, Mailchimp…) rewrite the links of the mails they send; the known ones
are recognized, but not all. For the domains listed in `trusted_domains` (the organization's own domains, for
example `["example.org"]`), a mail whose sender belongs to one of them is not flagged for its links or for brand
names in its link domains, provided that DMARC was validated by the receiving server (a sender only authenticated
by the internal verification is not trusted, nor is a spoofed one). Dangerous attachments, lookalike domains,
blocklisted domains and antispam verdicts still count: an account of a trusted sender can be compromised.

### Reputation checks

The analysis queries DNS blocklists for the IP address of the sending server and the domains of the mail (sender,
Reply-To, Return-Path, DKIM signers, links), and the registries (RDAP, through the IANA bootstrap) for the age of
these domains. These services receive the addresses and domains of the analyzed mails.

```json
"reputation": {
  "disabled": false,
  "dnsbl_ip": ["zen.spamhaus.org", "bl.spamcop.net"],
  "dnsbl_domain": ["dbl.spamhaus.org", "multi.surbl.org"],
  "spamhaus_dqs_key": "",
  "rdap_disabled": false,
  "revocation_disabled": false
}
```

All fields are optional; the lists above are the defaults. Spamhaus refuses the queries coming through public or
shared DNS resolvers (most cloud providers): the page then says the list did not answer. A free
[Data Query Service](https://www.spamhaus.com/free-trial/free-data-query-service/) key for non-commercial use
solves it; pass it with the `MTK_SPAMHAUS_DQS_KEY` environment variable (`-e MTK_SPAMHAUS_DQS_KEY=...` with
`docker run`) rather than in the file. Some registries publish no RDAP service (`.ch`, `.li`): the age of their
domains is not shown. `revocation_disabled` skips the OCSP and CRL queries sent to the certification authorities
of S/MIME signatures (also skipped when `disabled` is set).

## Deployment

The reference deployment (`mtk.kite-project.net`): the web site behind the Cloudflare proxy, the mails
received directly on port 25, everything in one Docker container.

1. **DNS** (Cloudflare):

   | Name                      | Type | Value                       | Proxy                     |
   |---------------------------|------|-----------------------------|---------------------------|
   | `mtk.kite-project.net`    | A    | IP of the server            | proxied (orange cloud)    |
   | `mx.mtk.kite-project.net` | A    | IP of the server            | **DNS only** (grey cloud) |
   | `mtk.kite-project.net`    | MX   | `10 mx.mtk.kite-project.net`|                           |

   Cloudflare only proxies the web: the MX must point to a DNS only name, or no mail arrives. The addresses
   are created in the domain of `domains` (`…@mtk.kite-project.net`), `hostname` is the MX name.

2. **Firewall**: open the incoming ports 25 (mails), 587 (optional, direct submission), 80 and 443.

3. **Code and configuration**, on the server:

   ```sh
   git clone https://github.com/get-code-ch/mailtoolkit_webserver.git
   cd mailtoolkit_webserver
   ```

   `conf/configuration.json` holds the reference configuration: adapt `hostname` and `domains`. Keep
   `"behind_cloudflare": true` when the site is proxied, so that the rate limits apply per visitor.

4. **Certificate**: behind Cloudflare a self-signed certificate is enough, with the SSL/TLS mode **Full**
   (not *Full (strict)*); mail servers do not check the certificate of an MX for STARTTLS either.

   ```sh
   mkdir -p ssl data
   openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=mtk.kite-project.net" \
     -addext "subjectAltName=DNS:mtk.kite-project.net,DNS:mx.mtk.kite-project.net" \
     -keyout ssl/server.key -out ssl/server.crt
   ```

   For *Full (strict)*, use a Cloudflare Origin CA certificate instead; without Cloudflare, a Let's Encrypt
   certificate (`certbot certonly --webroot -w ./acme -d <host>`, the HTTP port serves the challenges and
   renewals are picked up without restart). `ssl/` is ignored by git.

5. **Build and run**:

   ```sh
   docker build -t mailtoolkit_webserver .
   docker run -d --name mail-analyzer --restart unless-stopped \
     --user "$(id -u):$(id -g)" \
     -p 25:25 -p 587:587 -p 80:80 -p 443:443 \
     -v "$PWD/conf:/app/conf:ro" \
     -v "$PWD/ssl:/app/ssl:ro" \
     -v "$PWD/data:/app/data" \
     mailtoolkit_webserver
   ```

   - the configuration and the certificate are mounted read only: after a change, `docker restart mail-analyzer`
     is enough, no rebuild;
   - `--user` runs the server as the owner of the folder, which can read `ssl/server.key` and write in `data/`;
   - publish 465 too if `smtps` is enabled in the configuration.

6. **Check**:

   ```sh
   docker logs mail-analyzer       # one "listening" line per port
   nc mx.mtk.kite-project.net 25   # 220 mx.mtk.kite-project.net ESMTP ready
   ```

   then create an address on `https://mtk.kite-project.net` and forward a mail to it as an attachment.

**Update**: `git pull`, `docker build -t mailtoolkit_webserver .`, then `docker rm -f mail-analyzer` and the
`docker run` command again; the mailboxes in `data/` are kept.

## Without port 25: Cloudflare Email Routing

Mail servers deliver to the MX on port 25 only. When the host blocks it, Cloudflare Email Routing can receive
the mails and an Email Worker forwards them to the server over HTTPS (`POST /ingest`):

1. Generate a secret and give it to the server, never in a committed file:

   ```sh
   export MTK_INGEST_TOKEN=$(openssl rand -hex 32)
   ```

   (`-e MTK_INGEST_TOKEN=...` with Docker).
2. In Cloudflare, enable **Email Routing** for the domain of the addresses (it publishes its own MX records).
3. Create a Worker with `cloudflare/email-worker.js`, a variable `INGEST_URL`
   (`https://<host>/ingest`) and a secret `INGEST_TOKEN` (the same value).
4. Add a **catch-all** routing rule with the action *Send to a Worker*.

Unknown or expired addresses are rejected (the server answers 404 and the Worker rejects the mail); the other
errors are temporary. Without token, `/ingest` is disabled.

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
