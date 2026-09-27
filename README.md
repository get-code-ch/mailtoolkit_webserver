# mailtoolkit_webserver

Demo web server for [mailtoolkit](https://github.com/get-code-ch/mailtoolkit): lists the mails of a folder and displays their contents and attachments.

Requires Go 1.24 or later.

## Run

```sh
go run .
```

The server reads `./conf/configuration.json`:

| Field           | Description                                          |
|-----------------|------------------------------------------------------|
| `Server`/`Port` | listening address, `""` and `"80"` by default        |
| `mail_folder`   | folder containing the mails (`.eml` files)           |
| `ext`           | mail file extension, `.*` for every file             |
| `static_folder` | CSS and other static files                           |
| `ssl`           | serve HTTPS with the `Cert` and `Key` files          |

Mails are parsed on first access and reparsed when their file changes.

## Security

Mail contents come from third parties. They are displayed in a sandboxed iframe and served with a `Content-Security-Policy: sandbox` header: scripts do not run and remote images (tracking pixels) are not loaded. Attachments are always downloaded, never displayed.

## TLS

The certificate and private key are not stored in the repository. For a local self-signed certificate:

```sh
mkdir -p ssl
openssl req -x509 -newkey rsa:4096 -nodes -days 365 -subj "/CN=localhost" \
  -keyout ssl/server.key -out ssl/server.crt
```

## Docker

```sh
docker build -t mailtoolkit_webserver .
docker run -p 8080:80 mailtoolkit_webserver
# with TLS ("ssl": true in the configuration)
docker run -p 8443:80 -v "$PWD/ssl:/app/ssl:ro" mailtoolkit_webserver
```

## Developing with a local mailtoolkit

To work on both modules at once, create a `go.work` file in the parent folder:

```sh
go work init ./mailtoolkit ./mailtoolkit_webserver
```
