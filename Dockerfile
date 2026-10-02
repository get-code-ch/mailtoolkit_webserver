FROM golang:1.25-alpine AS builder

WORKDIR /src
# Download dependencies first to benefit from the layer cache
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o /out/mailtoolkit_webserver .


FROM alpine:3.22
LABEL org.opencontainers.image.authors="Claude Debieux <claude@get-code.ch>"

RUN addgroup -S app && adduser -S -G app app \
    && mkdir -p /app/data /app/acme \
    && chown app:app /app/data /app/acme
WORKDIR /app

COPY ./conf /app/conf
COPY ./static /app/static
COPY --from=builder /out/mailtoolkit_webserver /app/mailtoolkit_webserver

# Received mails (deleted after the retention delay)
VOLUME /app/data
# TLS certificate and key are not part of the image, mount them:
# -v /etc/letsencrypt/live/<domain>:/app/ssl:ro
USER app
# SMTP (MX, SMTPS, submission), HTTP, HTTPS. Docker lets unprivileged users
# bind ports below 1024 inside the container.
EXPOSE 25 465 587 80 443
ENTRYPOINT ["/app/mailtoolkit_webserver"]
