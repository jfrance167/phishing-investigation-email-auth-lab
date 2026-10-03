# Approved implementation plan

User approved the supplied architecture and implementation on October 1, 2026. Success requires running, evidenced experiments and reset/replay, not just prepared files.

1. Preflight/source selection: read relevant vault/design evidence; inspect toolkit; inventory host; select official signed packages and verify downloads; preserve unrelated work.
2. Isolation: create two named disposable Debian guests; provision temporarily; remove NAT; internal experiment network plus host-restricted management; verify IPv4/IPv6, guest and host forwarding, sockets and permitted/denied local traffic. No external probes.
3. Baseline: Postfix → Rspamd → Mailpit, local BIND DNS, disposable signing keys; prove SPF/DKIM/DMARC run on private IPs and preserve SMTP inputs. Baseline must pass before scenario traffic.
4. Matrix/reporting: define expected outcomes first; execute identity/alignment/policy/DNS/content/forgery/rotation cases; add relay; hold quarantine in Postfix queue and prove reject at SMTP; collect real aggregate XML and assess RFC 9990 compatibility.
5. Reset/replay: export and validate hashes before a named-resource reset; repeat baseline/representative cases and compare semantic outcomes.
6. Review package: analyst capstones supported by observed evidence, setup/run/reset documentation, security baseline workflows, secrets scan, handoff and pending Obsidian milestone. Keep everything local.

Research recommendation: adopt upstream Postfix/Rspamd/Mailpit/BIND/Swaks rather than fork or implement authentication cryptography. Build only orchestration and evidence/trust adapters. Rspamd's local skip defaults and legacy DMARC behavior require explicit configuration and observed tests. Mailpit's UI remote CSS/font control does not isolate host-side images or clicks, so use raw/text evidence review.

Boundaries: no public-provider tests, remote repository, push, publication, merge, paid calls, malware, credential collection, ARC/SRS, or unrelated host/network changes. Installation/reboot of a host hypervisor would require a material-change discussion; the installed VirtualBox avoids it. If runtime is unavailable, finish independent preparation and identify exact not-run checks without fabricating results.
