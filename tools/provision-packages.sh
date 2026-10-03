#!/bin/sh
# Run as root on a marked disposable Debian 13 guest during provisioning only.
set -eu
role=${1:?sender or receiver or relay}
case "$role" in sender|receiver|relay) ;; *) exit 2;; esac
[ "$(cat /etc/peal-owned)" = "PEAL-$role" ] || exit 2
[ "$(. /etc/os-release; echo "$VERSION_CODENAME")" = trixie ] || exit 2
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --no-install-recommends -y ca-certificates curl gpg nftables python3 swaks dnsutils rsyslog postfix redis-server
systemctl stop postfix
install -d -m 0755 /etc/apt/keyrings /opt/peal
curl --fail --proto '=https' --tlsv1.2 https://rspamd.com/apt-stable/gpg.key -o /opt/peal/rspamd-gpg.key
echo '218ef36314c2e4c8a0b05702cf7489c12e18e69916e805d806e6464d87277bec  /opt/peal/rspamd-gpg.key' | sha256sum -c -
gpg --batch --yes --dearmor -o /etc/apt/keyrings/rspamd.gpg /opt/peal/rspamd-gpg.key
printf '%s\n' 'deb [signed-by=/etc/apt/keyrings/rspamd.gpg] https://rspamd.com/apt-stable/ trixie main' > /etc/apt/sources.list.d/rspamd.list
apt-get update
candidate=$(apt-cache policy rspamd | sed -n 's/ *Candidate: //p')
case "$candidate" in 4.2.1*) ;; *) echo 'Selected Rspamd 4.2.1 unavailable: block experiments' >&2; exit 3;; esac
apt-get install --no-install-recommends -y "rspamd=$candidate"
systemctl stop rspamd
if [ "$role" = receiver ]; then
    apt-get install --no-install-recommends -y bind9
    systemctl stop named
fi
# Password credentials were used only by installation. SSH keys become the sole login method.
passwd -l root
passwd -l lab
printf '%s\n' 'PasswordAuthentication no' 'KbdInteractiveAuthentication no' 'PermitRootLogin prohibit-password' > /etc/ssh/sshd_config.d/peal.conf
sshd -t
systemctl reload ssh
dpkg-query -W > /opt/peal/packages.tsv
gpg --show-keys --with-colons /opt/peal/rspamd-gpg.key > /opt/peal/repository-key.txt
echo 'Provisioned packages. Still not ready for experiments.'
