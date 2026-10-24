# Deploying with deploy.sh

[Version française](deploy_fr.md)

`deploy.sh` rebuilds the image and recreates the `mail-analyzer` container with the same options as the
[Deployment](../README.md#deployment) section of the README, plus the secrets (keys of the threat databases, admin
and ingest tokens) read from a file kept outside the project. The mailboxes in `data/` are kept.

## Usage

```sh
./deploy.sh          # rebuild from the current checkout
./deploy.sh --pull   # git pull --ff-only first
```

The script can be started from any folder: it finds the project from its own location.

| Variable          | Default                          | Role |
|-------------------|----------------------------------|------|
| `MTK_PROJECT_DIR` | the folder of `deploy.sh`        | sources, used to build the image |
| `MTK_RUNTIME_DIR` | `MTK_PROJECT_DIR`                | folder holding `conf/`, `ssl/` and `data/`, mounted in the container |
| `MTK_SECRETS`     | `/etc/mailtoolkit/secrets.env`   | secrets passed to the container with `--env-file` |

These variables are read from the environment of the script only. Written in the secrets file, they would reach the
container, not the script.

Example, with the configuration, certificate and mailboxes in `/opt`:

```sh
MTK_RUNTIME_DIR=/opt/mailtoolkit_webserver ./deploy.sh
```

## Secrets file

The secrets stay out of the project, so that they are never committed nor sent in the Docker build context.
`secrets.env.example` is the model:

```sh
sudo install -d -m 750 -o "$USER" -g "$USER" /etc/mailtoolkit
install -m 600 secrets.env.example /etc/mailtoolkit/secrets.env
```

- One `VAR=value` per line, without quotes nor spaces around `=`: Docker takes the line as it is. Lines starting
  with `#` are ignored.
- An empty value disables the service, the server ignores it.
- The file must belong to the user running the script (not `root` with mode 600): the `docker` command reads it, not
  the daemon. It must not be readable by other users (600 or 640).
- The values are read when the container is created: after a change, run `deploy.sh` again, `docker restart` is not
  enough.

The variables are described in [External services](external-services.md) and in the
[Configuration](../README.md#configuration) section of the README.

## What the script does

1. Checks, before touching the running container, that `conf/configuration.json`, `ssl/server.crt` and
   `ssl/server.key` of `MTK_RUNTIME_DIR` are readable, that `data/` is writable, and that the secrets file exists and
   is not readable by everyone. The container runs as the current user (`--user`), so these files must belong to
   that user.
2. Runs `git pull --ff-only` with `--pull`.
3. Builds the image before stopping the running container, to keep the downtime short.
4. Removes the container and starts a new one: ports 25, 587, 80 and 443, `conf/` and `ssl/` read only, `data/`
   writable, `--restart unless-stopped`.
5. Shows the logs after 3 seconds.

## Checking the deployment

The first log line shows the configuration; the secrets appear as `(set)` when they reached the server, without
their value:

```
Configuration {... ThreatIntel:{AbuseCHKey:(set) SafeBrowsingKey: VirusTotalKey:} ... AdminToken:(set)}
SMTP (MX) listening on :25
SMTP (submission) listening on :587
HTTPS listening on :443
HTTP (redirect) listening on :80
```

The names of the variables received by the container, without their values:

```sh
docker exec mail-analyzer env | grep -o '^MTK_[A-Z_]*='
```

## Errors

| Message | Fix |
|---------|-----|
| `<dir>/ssl/server.key absent ou illisible par <user>` | copy the file, or give the folder to the user: `sudo chown -R "$USER": <dir>` |
| `<dir>/data absent ou non modifiable par <user>` | same, `data/` and its subfolders must belong to the user |
| `<file> absent ou illisible : voir secrets.env.example` | create the secrets file, owned by the user |
| `<file> est accessible à tous : chmod 600 ou 640` | `chmod 600 <file>` |

The running container is left untouched by these errors and by a failed build.

## Limits

- Port 465 (`smtps`) is not published; add `-p 465:465` to the script when it is enabled in the configuration.
- A container started by hand with other options or variables loses them: put the variables in the secrets file.
- Mailboxes are those of the mounted `data/`: switching `MTK_RUNTIME_DIR` to another folder does not move them.
