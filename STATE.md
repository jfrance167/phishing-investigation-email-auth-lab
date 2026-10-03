# Lab state

Authorization: October 1 implementation through local testing/documentation; October 2–3 review and complete. No remote creation, publication, push or merge.

Phase: **local implementation and agent review complete**. All 31 real authentication cases passed and their identities, nonce linkage, intended selectors and hashes were audited. Nine real replay outcomes match earlier measured passes. Final-source baseline/rotation pass; two actual aggregate reports exactly correlate three exclusive-window messages (1790999960–1791000006 UTC). Twenty-one offline tests pass; Bandit 1.9.4 zero findings. Full final three-guest isolation gate and all six local connectivity expectations pass.

Review resolutions: verified queue/run cleanup ledger, actual selector DNS/signature checks, failed rotation exit, shared pre-mutation readiness gates, bounded actual reads, report header/time validation, complete SMTP identity assertions, current exact queue logs and seal after successful restoration. Separate SPF-only/DKIM-only alignment controls added. See docs/REVIEW.md for concrete findings and limitations. This is Codex self-review; independent human security review remains recommended before publication.

Runtime: Windows 11 Home, VirtualBox 7.2.6r172322, i7-11800H/64 GiB. Three owned Debian 13.7 guests remain running on isolated PEAL-experiment plus restricted host-only management. NIC3–8 disabled; no NAT/bridge/default route/forwarding; guest IPv6 disabled. Private VM/SSH/signing material remains ignored. Guest package revisions accompany evidence. Preserve unrelated triage-toolkit working-copy changes; only its offline parser was reused.

Active core bugs: none known from the executed checks. Failed/partial attempts remain preserved. Run tools serially; after host suspension repair owned guest clocks with sync_clock, then require the full gate. SSH loss can block restoration, leaving an unsealed attempt that requires recovery before another submission. Keep at least 8 GiB host disk free.

Next local use: README and REVIEW_HANDOFF.md provide commands; use fresh outputs and inspect raw text/JSON only. Local review commit is on codex/phishing-email-auth-lab; use git rev-parse HEAD and git status --short for current identity. Relevant Obsidian review note is pending outside this repository; vault was not updated.

External work remains unexecuted: GitHub CI/CodeQL, visibility/eligibility, branch protections, secret scanning/push protection and Dependabot require publication scope. No remote exists. Verified limits: ISO signed-checksum signature not checked; legacy DMARC/report behavior and separate same-day adapter; no full transitive CVE/XSD conformance audit; no ARC/SRS. No claim of production readiness or exhaustive vulnerability absence.
