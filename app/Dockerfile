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

COPY conf /app/conf
COPY static /app/static
COPY view /app/view
COPY mail /app/mail
COPY ssl /app/ssl
COPY --from=builder /go/bin/mailtoolkit_webserver /app/mailtoolkit_webserver

ENTRYPOINT ["/app/mailtoolkit_webserver"]
