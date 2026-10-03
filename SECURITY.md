# Security model and reporting

This is a disposable, locally owned synthetic training lab, not an Internet mail gateway.
Experiment entry requires Test-LabReady.ps1 and local permitted/denied connectivity evidence.
Never attach experiment guests to NAT or a bridged adapter. Host-only management is restricted
to SSH from the host; host and guests must not forward packets. Review raw/text exports only.

Treat mail headers as claims, including a copied receiver authserv-id. Trusted evaluation requires
pinned out-of-band receiver collection and run/queue correlation with SMTP, logs and disposition.
Guest root and host administrators remain trusted; file hashes cannot defend against their compromise.

Python runtime uses the standard library. Bandit 1.9.4 is a development tool. Action pins were
resolved against official GitHub tag APIs on October 2, 2026. CI does not start VMs or send mail.
Before public use, manually review authentication settings, remote command construction, XML bounds,
reset ownership checks and ingress header handling. Scope and limitations are in docs/THREAT_MODEL.md.

Report defects privately to the repository owner through an available private channel. Use GitHub private vulnerability reporting when enabled on this repository. Do not include credentials or private mail.

Publication scan: Gitleaks 8.30.1 reviewed all reachable local commits. The only initial findings were an empty disabled VirtualBox teleporter setting whose multiline match continued into a VM identifier, and two values shipped publicly in Rspamd 4.2.1 fuzzy_check/rspamd_update configuration. All occurrences were compared against the official versioned source. `.gitleaks.toml` permits only those exact values/empty setting, retains default detection and does not exclude evidence paths or whole rules. See https://github.com/rspamd/rspamd/tree/4.2.1/conf/modules.d . Those remote modules are disabled in this lab.
