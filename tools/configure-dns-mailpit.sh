#!/bin/sh
set -eu
[ "$(cat /etc/peal-owned)" = PEAL-receiver ] || exit 2
# Copy only public .dns records from the sender into /opt/peal before running.
test -s /opt/peal/sender.test.lab1.dns
test -s /opt/peal/lookalike.test.lab1.dns
cat > /etc/bind/named.conf.options <<'EOF'
options {
 directory "/var/cache/bind";
 listen-on {127.0.0.1;10.77.0.20;}; listen-on-v6 {none;};
 recursion no; allow-query {127.0.0.1;10.77.0.0/24;};
 dnssec-validation no; empty-zones-enable no;
};
EOF
cat > /etc/bind/named.conf.local <<'EOF'
zone "test" {type primary; file "/etc/bind/peal.test.zone";};
EOF
cat > /etc/bind/peal.test.zone <<'EOF'
$ORIGIN test.
$TTL 30
@ IN SOA ns.recipient.test. analyst.recipient.test. (2026100101 30 30 3600 30)
@ IN NS ns.recipient.test.
ns.recipient IN A 10.77.0.20
receiver.recipient IN A 10.77.0.20
sender IN A 10.77.0.10
sender.sender IN A 10.77.0.10
relay IN A 10.77.0.30
recipient IN A 10.77.0.20
recipient IN MX 10 receiver.recipient.test.
sender IN TXT "v=spf1 ip4:10.77.0.10 -all"
lookalike IN TXT "v=spf1 ip4:10.77.0.10 -all"
bounce.sender IN TXT "v=spf1 ip4:10.77.0.10 -all"
_dmarc.sender IN TXT "v=DMARC1; p=none; rua=mailto:reports@recipient.test; adkim=r; aspf=r"
_dmarc.lookalike IN TXT "v=DMARC1; p=none; rua=mailto:reports@recipient.test"
sender.test._report._dmarc.recipient IN TXT "v=DMARC1"
lookalike.test._report._dmarc.recipient IN TXT "v=DMARC1"
EOF
for domain in sender.test lookalike.test; do
 printf '\n$ORIGIN %s.\n' "$domain" >> /etc/bind/peal.test.zone
 cat "/opt/peal/$domain.lab1.dns" >> /etc/bind/peal.test.zone
done
named-checkconf
named-checkzone test /etc/bind/peal.test.zone
echo 'e98b9a8d9622417a6988b736f7d3246e94bad4fed48ad3c604e60d72569f8cc7  /opt/peal/mailpit-linux-amd64.tar.gz' | sha256sum -c -
if systemctl list-unit-files mailpit.service --no-legend | grep -q mailpit; then systemctl stop mailpit; fi
python3 - <<'PY'
import tarfile
from pathlib import Path
with tarfile.open('/opt/peal/mailpit-linux-amd64.tar.gz') as archive:
    member = archive.getmember('mailpit')
    if not member.isfile() or member.size > 100_000_000:
        raise ValueError('Unexpected Mailpit archive member')
    with archive.extractfile(member) as source:
        Path('/usr/local/bin/mailpit').write_bytes(source.read())
PY
chmod 755 /usr/local/bin/mailpit
id mailpit >/dev/null 2>&1 || useradd --system --home /var/lib/mailpit --shell /usr/sbin/nologin mailpit
install -d -m 0700 -o mailpit -g mailpit /var/lib/mailpit
cat > /etc/systemd/system/mailpit.service <<'EOF'
[Unit]
Description=Disposable lab capture (loopback only)
After=network.target
[Service]
User=mailpit
Group=mailpit
ExecStart=/usr/local/bin/mailpit --smtp 127.0.0.1:1025 --listen 127.0.0.1:8025 --database /var/lib/mailpit/messages.db --max 0 --max-message-size 2 --disable-version-check --block-remote-css-and-fonts --allowed-hosts localhost,127.0.0.1
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/mailpit
PrivateTmp=true
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mailpit named
systemctl restart named mailpit
# The standalone version subcommand performs its own release lookup; use service startup logs instead.
echo 'DNS/capture configured; still require integration baseline.'
