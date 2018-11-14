FROM alpine:latest
MAINTAINER Claude Debieux <claude@get-code.ch>

RUN apk add --no-cache --update supervisor rsyslog bash postfix ca-certificates openssl dovecot

# postfix conf
RUN mkdir -p /var/run/postfix
COPY ./etc/ /etc/postfix/

RUN sed -i -e "s/##MYHOSTNAME##/$HOSTNAME/g" /etc/postfix/main.cf

RUN postmap /etc/postfix/vmail_domains
RUN postmap /etc/postfix/vmail_mailbox
RUN postmap /etc/postfix/vmail_alias
RUN postalias hash:/etc/postfix/aliases

RUN touch /var/log/maillog

# dovecot conf
COPY ./dovecot/ /etc/dovecot/
RUN chmod +r /etc/dovecot/users
RUN touch /var/log/dovecot

# certificat install
COPY ./ssl /etc/ssl/certs/

# supervisor
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]