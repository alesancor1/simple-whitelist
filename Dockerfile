FROM alpine:3.22

RUN apk add --no-cache \
    bash \
    bind-tools \
    ipset \
    iptables

COPY whitelist.sh /usr/local/bin/whitelist.sh
COPY whitelist.txt.template /templates/whitelist.txt.template

RUN chmod +x /usr/local/bin/whitelist.sh

ENTRYPOINT ["/usr/local/bin/whitelist.sh"]
