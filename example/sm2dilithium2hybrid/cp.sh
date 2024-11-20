#!/bin/bash

cp ca.pem /usr/local/strongswan/etc/swanctl/x509ca/
cp 7549d76e-82b7-4bc0-a990-a5bc1a0af36b.key /usr/local/strongswan/etc/swanctl/private/
cp 7549d76e-82b7-4bc0-a990-a5bc1a0af36b.pem /usr/local/strongswan/etc/swanctl/x509/

scp ca.pem root@192.168.56.107:/usr/local/strongswan/etc/swanctl/x509ca/
scp e963dbc5-7319-44d1-a071-8e6eef321747.key root@192.168.56.107:/usr/local/strongswan/etc/swanctl/private/
scp e963dbc5-7319-44d1-a071-8e6eef321747.pem root@192.168.56.107:/usr/local/strongswan/etc/swanctl/x509/
