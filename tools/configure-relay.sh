#!/bin/sh
set -eu
[ "$(cat /etc/peal-owned)" = PEAL-relay ] || exit 2
test -s /opt/peal/relay_filter.py
id pealrelay >/dev/null 2>&1 || useradd --system --home /var/lib/peal-relay --shell /usr/sbin/nologin pealrelay
install -d -m 0700 -o pealrelay -g pealrelay /var/lib/peal-relay
chmod 755 /opt/peal/relay_filter.py
postconf -e 'myhostname = relay.sender.test' 'inet_interfaces = 127.0.0.1,10.77.0.30' 'inet_protocols = ipv4' 'mynetworks = 127.0.0.0/8' 'mydestination =' 'relay_domains = recipient.test' 'relay_recipient_maps =' 'smtpd_relay_restrictions = reject_unauth_destination' 'smtpd_recipient_restrictions = reject_unauth_destination' 'smtpd_milters =' 'non_smtpd_milters =' 'smtp_bind_address = 10.77.0.30' 'smtp_tls_security_level = none' 'smtpd_tls_security_level = none' 'message_size_limit = 2097152' 'content_filter = pealfilter:dummy' 'transport_maps = hash:/etc/postfix/peal-transport'
printf '%s\n' 'recipient.test smtp:[10.77.0.20]:25' > /etc/postfix/peal-transport
postmap /etc/postfix/peal-transport
# Idempotently own only the named service definitions, preserving the standard master file.
python3 - <<'PY'
from pathlib import Path
p=Path('/etc/postfix/master.cf')
text=p.read_text().split('# BEGIN PEAL RELAY')[0]
p.write_text(text+'''# BEGIN PEAL RELAY
pealfilter unix - n n - 1 pipe
  flags=Rq user=pealrelay argv=/usr/bin/python3 /opt/peal/relay_filter.py ${sender} ${recipient}
127.0.0.1:10026 inet n - n - - smtpd
  -o content_filter=
  -o smtpd_milters=
  -o receive_override_options=no_header_body_checks,no_milters
  -o smtpd_client_restrictions=permit_mynetworks,reject
  -o smtpd_relay_restrictions=permit_mynetworks,reject
  -o smtpd_recipient_restrictions=permit_mynetworks,reject
  -o mynetworks=127.0.0.0/8
''')
PY
postfix check
systemctl restart postfix
