#!/bin/sh
# Rebuilds the image and recreates the mail-analyzer container with the
# secrets of the secrets file (keys of the threat databases, admin and
# ingest tokens). The mailboxes in data/ are kept.
#
#   ./deploy.sh          rebuild from the current checkout
#   ./deploy.sh --pull   git pull first
#
# MTK_PROJECT_DIR (sources, default: the folder of this script),
# MTK_RUNTIME_DIR (conf/, ssl/ and data/, default: MTK_PROJECT_DIR) and
# MTK_SECRETS (default: /etc/mailtoolkit/secrets.env) override the paths.
set -eu

PROJECT_DIR=${MTK_PROJECT_DIR:-$(cd "$(dirname "$0")" && pwd)}
RUNTIME_DIR=${MTK_RUNTIME_DIR:-$PROJECT_DIR}
SECRETS=${MTK_SECRETS:-/etc/mailtoolkit/secrets.env}
NAME=mail-analyzer
IMAGE=mailtoolkit_webserver

# The container runs as the current user: it must read the configuration
# and the certificate, and write the mailboxes.
for f in conf/configuration.json ssl/server.crt ssl/server.key; do
	if [ ! -r "$RUNTIME_DIR/$f" ]; then
		echo "$RUNTIME_DIR/$f absent ou illisible par $(id -un)" >&2
		exit 1
	fi
done
if [ ! -w "$RUNTIME_DIR/data" ] || [ ! -x "$RUNTIME_DIR/data" ]; then
	echo "$RUNTIME_DIR/data absent ou non modifiable par $(id -un)" >&2
	exit 1
fi

if [ ! -r "$SECRETS" ]; then
	echo "$SECRETS absent ou illisible : voir secrets.env.example" >&2
	exit 1
fi
# The file must not be readable by other users.
if [ -n "$(find "$SECRETS" -perm /o=rwx)" ]; then
	echo "$SECRETS est accessible à tous : chmod 600 ou 640" >&2
	exit 1
fi

if [ "${1:-}" = "--pull" ]; then
	git -C "$PROJECT_DIR" pull --ff-only
fi

# Build before stopping the running container, to keep the downtime short.
docker build -t "$IMAGE" "$PROJECT_DIR"

docker rm -f "$NAME" 2>/dev/null || true
docker run -d --name "$NAME" --restart unless-stopped \
	--user "$(id -u):$(id -g)" \
	--env-file "$SECRETS" \
	-p 25:25 -p 587:587 -p 80:80 -p 443:443 \
	-v "$RUNTIME_DIR/conf:/app/conf:ro" \
	-v "$RUNTIME_DIR/ssl:/app/ssl:ro" \
	-v "$RUNTIME_DIR/data:/app/data" \
	"$IMAGE"

sleep 3
docker logs "$NAME"
