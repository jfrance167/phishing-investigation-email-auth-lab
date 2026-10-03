#!/bin/sh
set -eu
role=${1:?sender or receiver}
case "$role" in sender|receiver) ;; *) exit 2;; esac
[ "$(cat /etc/peal-owned)" = "PEAL-$role" ] || exit 2
install -d /etc/rspamd/local.d /opt/peal
install -d /etc/rspamd/peal-modules
# Load only the selected authentication/integration modules. Default content rules create remote maps.
for module in spf dmarc dkim_signing milter_headers settings; do
 ln -sf "/usr/share/rspamd/plugins/$module.lua" "/etc/rspamd/peal-modules/$module.lua"
done
cat > /etc/rspamd/rspamd.conf.local.override <<'EOF'
lua = "/etc/rspamd/rspamd.local.lua";
filters = "dkim";
modules { path = "/etc/rspamd/peal-modules"; }
EOF
install -d -m 0700 -o _rspamd -g _rspamd /var/lib/rspamd/peal
cat > /etc/rspamd/local.d/options.inc <<'EOF'
dns { nameserver = ["10.77.0.20:53"]; timeout = 1s; retransmits = 1; }
url_tld = "/opt/peal/lab-tld.dat";
EOF
cp /usr/share/rspamd/effective_tld_names.dat /opt/peal/lab-tld.dat
printf '\n// Disposable lab suffix only\ntest\n' >> /opt/peal/lab-tld.dat
cat > /etc/rspamd/local.d/worker-proxy.inc <<'EOF'
bind_socket = "127.0.0.1:11332";
upstream "local" { self_scan = true; }
EOF
printf '%s\n' 'bind_socket = "127.0.0.1:11333";' > /etc/rspamd/local.d/worker-normal.inc
printf '%s\n' 'bind_socket = "127.0.0.1:11334";' > /etc/rspamd/local.d/worker-controller.inc
for module in spf dkim dmarc; do
 printf '%s\n' 'check_local = true; check_authed = true;' > "/etc/rspamd/local.d/$module.conf"
done
printf '%s\n' 'max_dns_requests = 10;' >> /etc/rspamd/local.d/spf.conf
for module in rbl surbl url_redirector fuzzy_check reputation mx_check asn external_services gpt greylist ratelimit antivirus phishing rspamd_update external_relay; do
 printf '%s\n' 'enabled = false;' > "/etc/rspamd/local.d/$module.conf"
done
cat > /etc/rspamd/local.d/actions.conf <<'EOF'
reject = 1000;
add_header = 999;
greylist = null;
quarantine { flags = ["no_threshold"]; }
EOF
cat > /etc/rspamd/local.d/redis.conf <<'EOF'
servers = "127.0.0.1";
EOF
cat > /etc/rspamd/local.d/milter_headers.conf <<'EOF'
use = ["authentication-results", "x-rspamd-queue-id"];
skip_local = false;
skip_authenticated = false;
routines { authentication-results { authserv_id = "receiver.recipient.test"; remove = 0; } }
EOF
cat > /etc/rspamd/local.d/settings.conf <<'EOF'
peal {
 priority = high;
 ip = "0.0.0.0/0";
 apply { symbols_enabled = ["SPF_CHECK", "DKIM_CHECK", "DMARC_CHECK", "DKIM_SIGNED", "MILTER_HEADERS", "PEAL_EVIDENCE"]; }
}
EOF
cat > /etc/rspamd/rspamd.local.lua <<'EOF'
local ucl = require 'ucl'
rspamd_config:register_symbol({
 name = 'PEAL_EVIDENCE', type = 'postfilter', priority = -100,
 callback = function(task)
  local qid = task:get_queue_id()
  if not qid or not qid:match('^[A-Za-z0-9]+$') then return end
  local data = {
   queue_id = qid, ip = tostring(task:get_ip()), helo = task:get_helo(),
   envelope_from = task:get_from('smtp'), envelope_to = task:get_recipients('smtp'),
   header_from = task:get_from('mime'), symbols = task:get_symbols_all(),
   action = task:get_metric_action(), collected_unix = os.time(),
   scenario_claim = task:get_header('X-Lab-Scenario'), run_claim = task:get_header('X-Lab-Run'), source = 'receiver-rspamd-milter'
  }
  local file = io.open('/var/lib/rspamd/peal/' .. qid .. '.json', 'w')
  if file then file:write(ucl.to_format(data, 'json')); file:close() end
 end
})
EOF
postconf -e 'milter_protocol = 6' 'milter_default_action = tempfail' 'smtpd_milters = inet:127.0.0.1:11332' 'non_smtpd_milters = inet:127.0.0.1:11332' 'smtpd_sasl_auth_enable = no' 'smtpd_tls_security_level = none' 'smtp_tls_security_level = none' 'inet_protocols = ipv4' 'mynetworks = 127.0.0.0/8' 'smtpd_relay_restrictions = reject_unauth_destination' 'smtpd_recipient_restrictions = reject_unauth_destination' 'message_size_limit = 2097152' 'mydestination =' 'relay_domains = recipient.test' 'relay_recipient_maps =' 'transport_maps = hash:/etc/postfix/peal-transport'
if [ "$role" = sender ]; then
 postconf -e 'myhostname = sender.sender.test' 'inet_interfaces = loopback-only' 'smtp_bind_address = 10.77.0.10'
 printf '%s\n' 'recipient.test smtp:[10.77.0.20]:25' > /etc/postfix/peal-transport
 cat > /etc/rspamd/local.d/dkim_signing.conf <<'EOF'
enabled = true;
sign_local = true;
sign_authenticated = false;
allow_envfrom_empty = true;
allow_hdrfrom_mismatch = true;
allow_username_mismatch = true;
use_domain = "envelope";
use_esld = false;
selector = "lab1";
path = "/var/lib/rspamd/dkim/$domain.$selector.key";
EOF
 install -d -m 0700 -o _rspamd -g _rspamd /var/lib/rspamd/dkim
 for domain in sender.test lookalike.test; do
  if [ ! -f "/var/lib/rspamd/dkim/$domain.lab1.key" ]; then
   rspamadm dkim_keygen -s lab1 -d "$domain" -b 2048 -k "/var/lib/rspamd/dkim/$domain.lab1.key" > "/opt/peal/$domain.lab1.dns"
   chown _rspamd:_rspamd "/var/lib/rspamd/dkim/$domain.lab1.key"
   chmod 600 "/var/lib/rspamd/dkim/$domain.lab1.key"
  fi
 done
else
 postconf -e 'myhostname = receiver.recipient.test' 'inet_interfaces = 127.0.0.1,10.77.0.20' 'header_checks = regexp:/etc/postfix/peal-header-checks'
 printf '%s\n' 'recipient.test smtp:[127.0.0.1]:1025' > /etc/postfix/peal-transport
 # Preserve submitted raw bytes outside the receiver first. Strip copyable result headers before milter.
 cat > /etc/postfix/peal-header-checks <<'EOF'
/^Authentication-Results:/ IGNORE
/^Received-SPF:/ IGNORE
/^X-Rspamd-/ IGNORE
EOF
 printf '%s\n' 'enabled = false;' > /etc/rspamd/local.d/dkim_signing.conf
 cat >> /etc/rspamd/local.d/dmarc.conf <<'EOF'
actions { reject = "reject"; quarantine = "quarantine"; softfail = "no action"; }
reporting {
 enabled = true; email = "reports@recipient.test"; domain = "recipient.test";
 org_name = "Disposable email lab"; smtp = "127.0.0.1"; smtp_port = 25;
 helo = "receiver.recipient.test"; bcc_addrs = ["reports@recipient.test"];
}
EOF
fi
postmap /etc/postfix/peal-transport
postfix check
rspamadm configtest
systemctl restart redis-server rspamd postfix
rspamadm configdump > /opt/peal/effective-rspamd.ucl
postconf -n > /opt/peal/effective-postfix.txt
echo 'Mail configured. Isolation and baseline verification still required.'
