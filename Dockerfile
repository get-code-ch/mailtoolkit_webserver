FROM golang:1.24-alpine AS builder

WORKDIR /src
# Download dependencies first to benefit from the layer cache
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-w -s" -o /out/mailtoolkit_webserver .


FROM alpine:3.22
LABEL org.opencontainers.image.authors="Claude Debieux <claude@get-code.ch>"

RUN addgroup -S app && adduser -S -G app app
WORKDIR /app

COPY ./conf /app/conf
COPY ./static /app/static
COPY ./mail /app/mail
COPY --from=builder /out/mailtoolkit_webserver /app/mailtoolkit_webserver

# TLS certificate and key are not part of the image, mount them when "ssl" is
# enabled in conf/configuration.json: -v /path/to/ssl:/app/ssl:ro
USER app
EXPOSE 80
ENTRYPOINT ["/app/mailtoolkit_webserver"]
