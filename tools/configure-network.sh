#!/bin/sh
# Stage static networking and firewall; activate only when NAT has been removed.
set -eu
role=${1:?role}
case "$role" in sender) mgmt=50; lab=10;; receiver) mgmt=51; lab=20;; relay) mgmt=52; lab=30;; *) exit 2;; esac
[ "$(cat /etc/peal-owned)" = "PEAL-$role" ] || exit 2
# Debian's installer enables dhcpcd; it must not acquire routes or overwrite lab DNS after reboot.
if systemctl list-unit-files dhcpcd.service --no-legend | grep -q dhcpcd; then
 systemctl disable dhcpcd.service
fi
systemctl mask dhcpcd.service
cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback
auto enp0s3
iface enp0s3 inet static
 address 192.168.56.$mgmt/24
auto enp0s8
iface enp0s8 inet static
 address 10.77.0.$lab/24
EOF
if [ "$role" = sender ]; then
    printf '%s\n' ' up ip addr add 10.77.0.11/24 dev enp0s8' >> /etc/network/interfaces
fi
printf '%s\n' 'nameserver 10.77.0.20' > /etc/resolv.conf
cat > /etc/sysctl.d/90-peal.conf <<'EOF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
EOF
# No flush of any other table. This guest must bear the ownership marker above.
cat > /etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
table inet peal {
 chain input {
  type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state established,related accept
  iifname "enp0s3" ip saddr 192.168.56.1 tcp dport 22 accept
  iifname "enp0s8" ip saddr {10.77.0.10,10.77.0.11,10.77.0.20,10.77.0.30} tcp dport {25,53} accept
  iifname "enp0s8" ip saddr {10.77.0.10,10.77.0.11,10.77.0.20,10.77.0.30} udp dport 53 accept
  iifname "enp0s8" ip saddr 10.77.0.0/24 ip protocol icmp accept
  counter drop
 }
 chain forward { type filter hook forward priority 0; policy drop; counter drop; }
 chain output {
  type filter hook output priority 0; policy drop;
  oifname "lo" accept
  ct state established,related accept
  oifname "enp0s8" ip daddr {10.77.0.10,10.77.0.11,10.77.0.20,10.77.0.30} tcp dport {25,53} accept
  oifname "enp0s8" ip daddr 10.77.0.20 udp dport 53 accept
  oifname "enp0s8" ip daddr 10.77.0.0/24 ip protocol icmp accept
  counter drop
 }
}
EOF
nft --check -f /etc/nftables.conf
systemctl enable nftables
echo 'Network staged; shut down, remove NAT, attach restricted management/internal NICs, then reboot.'
