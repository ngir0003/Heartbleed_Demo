#!/bin/sh
set -e

make-ssl-cert generate-default-snakeoil --force-overwrite 2>/dev/null || true

cat /etc/ssl/certs/ssl-cert-snakeoil.pem \
    /etc/ssl/private/ssl-cert-snakeoil.key \
    > /tmp/stunnel.pem

chmod 600 /tmp/stunnel.pem

cd /srv/www/app
python3 server.py &

sleep 2

exec stunnel /etc/stunnel/stunnel.conf
