# Fresh installation sequence

This is a Windows/VirtualBox recipe for named disposable guests. Run serially and retain private
files outside tracked source. It was exercised here with the source/runtime revisions in the handoff.

1. Run `tools/Get-Preflight.ps1` with its required fresh output path. Inspect host virtualization,
   memory/disk, existing VMs, host-only adapter and forwarding. The scripts expect the existing
   adapter `VirtualBox Host-Only Ethernet Adapter`, host 192.168.56.1/24, DHCP off. If absent or
   different, stop and review the management design; do not silently change unrelated adapters.
2. Place the official Debian 13.7.0 amd64 netinst ISO at `.private/debian-13.7.0-amd64-netinst.iso`.
   Expected SHA-256: `a7ef94ac2fb9a7fec454552abd629b7cc9d5155c886165a45649f5ce6167e355`.
   This installation checked the official HTTPS checksum, not the signed-checksum signature.
   Independently verify the Debian signature for a stronger fresh-install provenance check.
3. Generate a disposable Ed25519 SSH key at `.private/id_ed25519` with Windows OpenSSH `ssh-keygen`.
   Use a simple alphanumeric/hyphen comment. Verify the actual passphrase rather than relying on
   PowerShell quoting of an empty `-N` argument. Never commit the private key or installer logs.
4. Run `pwsh -File tools/New-LabVM.ps1 -Role sender`, then receiver and relay. Each refuses an
   existing name. Provisioning NAT has loopback SSH ports 22710/22720/22730. Wait for installation,
   verify console ownership and SSH host keys, and pin them in `.private/known_hosts` before access.
   VBox logs may contain disposable installer passwords; all unattended output stays private.
5. During provisioning only, copy and run `tools/provision-packages.sh ROLE` over the corresponding
   loopback SSH port. It checks `/etc/peal-owned`, Debian trixie, signed packages and the selected
   Rspamd release, then locks password accounts. Inspect exact package metadata. Download official
   Mailpit v1.31.3 `mailpit-linux-amd64.tar.gz` into receiver `/opt/peal/`; expected release-asset
   SHA-256 `e98b9a8d9622417a6988b736f7d3246e94bad4fed48ad3c604e60d72569f8cc7`.
6. Copy `tools/configure-network.sh` to each guest and run it with its role. It stages static
   management/internal addresses, no gateway, IPv6 disablement, disabled DHCP and nftables.
   Shut down the guest using `shutdown -h now`. Run `tools/Set-IsolatedNICs.ps1 -Role ROLE`.
   That tool requires the owned VM to be powered off, removes NAT, attaches host-only/internal
   NICs and starts it headless. Verify actual hypervisor NICs and guest routes/firewall before mail.
7. Verify guest host keys through the already pinned provisioning channel before management migration.
   Sender/receiver/relay SSH addresses become 192.168.56.50/.51/.52. The helpers use those fixed
   addresses and actual Windows OpenSSH executables; host-key mismatch must stop work.
8. Copy/run `configure-mail.sh sender` and `configure-mail.sh receiver`. Copy only sender public
   `/opt/peal/sender.test.lab1.dns` and `lookalike.test.lab1.dns` to receiver `/opt/peal/`.
   Copy/run `configure-dns-mailpit.sh` on receiver. Private DKIM keys remain inside the sender.
   Copy `relay_filter.py` and `configure-relay.sh` to relay `/opt/peal/` and run the latter.
9. Run the full readiness gate, the fixed local connectivity tests and S01 baseline. Proceed to
   the matrix only after isolated networking and observed SPF/DKIM/DMARC baseline pass.

For existing guests, reviewed copying helpers are `tools.lab.upload`, `download`, and `ssh`;
they use pinned SSH, fixed role addresses and single argv path arguments. Package/network
provisioning is deliberately separate from the experiment runner: a gate failure never adds NAT.
`Repair-ConsoleBootstrap.ps1` is preserved historical recovery for the initial two consoles; it
is not a general unattended installer or a required step in a fresh corrected bootstrap. It now
requires `-ConfirmFreshLogin` as an explicit operator assertion, requires the exact owned VM
configuration path and a running VM, and checks each VirtualBox keyboard operation. The switch
does not detect the visible guest console: before using it, the operator must verify the named
owned guest is showing a fresh tty login prompt. Do not use this recovery helper on another VM or
console. Its offline guard tests do not access VirtualBox or read credentials.

The evidence-manifest proposal streams SHA-256 input in 64 KiB chunks and rejects more than
16 MiB per file, 256 MiB total per bundle, 10,000 evidence files, or a 4 MiB manifest. These
limits are above the reviewed snapshot's 2,227 evidence files, 20,000 directory-entry cap,
17,474,908 bytes total and 119,836-byte largest file. The entry limit counts files and directories
and stops the lazy tree walk before sorting or hashing. Incremental SHA-256 preserves each existing
file digest; the manifest format is unchanged.
