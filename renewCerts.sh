#!/bin/sh
# This script renews all the Let's Encrypt certificates with a validity < 30 days

if ! /opt/letsencrypt/letsencrypt-auto renew > /var/log/letsencrypt/renew.log 2>&1 ; then
    echo Automated renewal failed:
    cat /var/log/letsencrypt/renew.log
    exit 1
fi
nginx -s reload
