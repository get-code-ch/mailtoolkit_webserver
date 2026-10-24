# External services

[Version française](external-services_fr.md)

The analysis can ask outside services about the links, attachments, sending server and domains of a mail. All of
them are optional: without them, the analysis of the mail itself (headers, DKIM, SPF, DMARC, links, attachments,
QR codes…) still runs. This page sums up how to register to each of them, and their limits.

The free offers of Google Safe Browsing, VirusTotal and Spamhaus DQS are for **non-commercial use** only: a public
service sold to customers, or run by a company for its own needs, needs their commercial licences. The terms change;
check them on the sites of the services before relying on this page.

## Summary

| Service | Checks | Key | Free limits |
|---------|--------|-----|-------------|
| URLhaus (abuse.ch) | hosts of the links, URLs on shared platforms | `MTK_ABUSECH_KEY` | fair use |
| MalwareBazaar (abuse.ch) | SHA-256 of the attachments | same key | fair use |
| Google Safe Browsing | hosts of the links, URLs on shared platforms | `MTK_SAFEBROWSING_KEY` | non-commercial, daily quota of the Cloud project |
| VirusTotal | SHA-256 of the attachments, domains of the links | `MTK_VIRUSTOTAL_KEY` | non-commercial, 4 queries a minute, 500 a day |
| Spamhaus ZEN and DBL | sending server, domains | `MTK_SPAMHAUS_DQS_KEY` | non-commercial, low volume |
| SpamCop, SURBL | sending server, domains | none | low volume |
| RDAP registries | registration date of the domains | none | — |
| S/MIME certification authorities | revocation (OCSP, CRL) | none | — |
| Sites of the links | final page of the suspicious links | none | — |

The keys are passed as environment variables, in the secrets file read by [deploy.sh](deploy.md), rather than in
`conf/configuration.json`. A service without key is not queried.

## Registration

### abuse.ch: URLhaus and MalwareBazaar

1. Log in on <https://auth.abuse.ch/> with an existing account (GitHub, Google, LinkedIn or X).
2. Copy the **Auth-Key** of the profile; the same key serves URLhaus and MalwareBazaar. Generating a new key
   invalidates the previous one.
3. `MTK_ABUSECH_KEY=<key>` in the secrets file, then `deploy.sh`.

### Google Safe Browsing

1. Create a project on <https://console.cloud.google.com/>.
2. *APIs & Services → Library*: enable the **Safe Browsing API**.
3. *Credentials → Create credentials → API key*; restrict the key to the Safe Browsing API and, if possible, to the
   address of the server.
4. `MTK_SAFEBROWSING_KEY=<key>`.

Commercial use requires the paid Web Risk API, which this server does not support.

### VirusTotal

1. Sign up on <https://www.virustotal.com/>.
2. The key is under **API key** in the profile menu.
3. `MTK_VIRUSTOTAL_KEY=<key>`.

### Spamhaus Data Query Service

1. Register on <https://www.spamhaus.com/free-trial/free-data-query-service/> and confirm the address.
2. The DQS key is shown in the Spamhaus portal.
3. `MTK_SPAMHAUS_DQS_KEY=<key>`.

Spamhaus refuses the queries coming through public or shared DNS resolvers, used by most cloud providers: without
this key, ZEN and DBL often do not answer from a hosted server.

### Without registration

SpamCop (`bl.spamcop.net`), SURBL (`multi.surbl.org`), the RDAP registries (found through the IANA bootstrap
`data.iana.org`), the OCSP and CRL servers of the certification authorities and the sites of the links are queried
without key.

## Volume per mail

The server bounds the queries of one analysis, and keeps the answers in memory (a restart empties the cache).

| Service | Per mail | Cache |
|---------|----------|-------|
| URLhaus | 12 hosts, 20 URLs | 6 h |
| MalwareBazaar | 5 attachments | 6 h |
| Google Safe Browsing | 1 request (every host and URL together) | 6 h |
| VirusTotal | 4 queries (attachments first, then domains of the links) | 6 h |
| DNS blocklists | sending server, 15 domains | — |
| RDAP | 8 domains | 24 h |
| Link following | 6 automatic visits, 15 s in all | — |

Errors are not cached: the next analysis asks again.

With the free VirusTotal key, a second mail analyzed within the same minute can exceed the quota; the page then says
the service did not answer.

## Privacy

The services learn what the server asks them:

- threat databases: host names, file hashes and, for the links of shared platforms (SharePoint, GitHub…), the URLs
  without their parameters, which often hold the address of the recipient;
- DNS blocklists and RDAP: the address of the sending server and the domains of the mail;
- link following: the visited sites see a visit from the address of the server, possibly the confirmation that the
  mail was opened. Single-use links (unsubscription, confirmation, reset) are never followed automatically.

`"reputation": {"disabled": true}` in the configuration stops the blocklists, RDAP, the threat databases and the link
following; `"link_visits": {"disabled": true}` stops the link following only; `"revocation_disabled": true` the OCSP
and CRL queries.

## Checking a service

On the page of an analysis, detailed view, the **External services** panel lists each service consulted, the items it was
asked about and its answer ("nothing known", "N reported" or "no answer"), then the services not configured. The
**Security** page (`/securite`) shows which services are enabled on the server.

On the page of an analysis, detailed view, section **Bases de menaces**:

| The page shows | Meaning |
|----------------|---------|
| « Aucun lien ni aucune pièce jointe n'est connu de URLhaus, … » | the listed services answered |
| « Sans réponse (clé refusée, quota atteint ou service indisponible) : … » | key refused, quota reached or service unreachable |
| « Aucune base de menaces n'est configurée sur ce serveur » | no key reached the server |

MalwareBazaar and the VirusTotal file queries are only made for a mail with attachments. The failures are not
written in the logs of the server; the first log line only says which keys are set (`AbuseCHKey:(set)`).

A key can be tested without the server, for example the abuse.ch one (HTTP 200 when it is accepted, 403
`unknown_auth_key` otherwise):

```sh
curl -s -o /dev/null -w 'HTTP %{http_code}\n' -H "Auth-Key: $(sed -n 's/^MTK_ABUSECH_KEY=//p' /etc/mailtoolkit/secrets.env)" -d host=example.com https://urlhaus-api.abuse.ch/v1/host/
```

`example.com` is listed by URLhaus: do not use it as a harmless link in a test mail.

## Limits

- The databases only know what was already reported: a new phishing site is often unknown for hours.
- The DNS blocklists, DKIM keys and RDAP data are read at the time of the analysis, not at the time the mail was sent.
- Some registries publish no RDAP service (`.ch`, `.li`): the age of their domains is not shown.
- Spamhaus without DQS key and SURBL can refuse the queries of shared resolvers; the page lists the zones that did not
  answer.
