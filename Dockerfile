FROM golang:alpine as builder

RUN apk update && apk add git

COPY . $GOPATH/src/mailtoolkit_webserver
WORKDIR $GOPATH/src/mailtoolkit_webserver
#get dependancies
#you can also use dep
RUN go get -d -v
#build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build  -a -installsuffix cgo -ldflags="-w -s" -o /go/bin/mailtoolkit_webserver


FROM alpine:latest
MAINTAINER Claude Debieux <claude@get-code.ch>

RUN apk add --no-cache --update bash ca-certificates openssl
WORKDIR /app

COPY app/conf /app/conf
COPY app/static /app/static
COPY app/view /app/view
COPY app/mail /app/mail
COPY app/ssl /app/ssl
COPY --from=builder /go/bin/mailtoolkit_webserver /app/mailtoolkit_webserver

EXPOSE 80
ENTRYPOINT ["/app/mailtoolkit_webserver"]
