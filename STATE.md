# Lab state

Authorization: October 1 implementation through local testing/documentation; October 2–3 review and complete. October 3: Jake authorized GitHub publication and notification to the running review chat. October 3 follow-up: Jake authorized review/merge of the 23 portfolio remediation PRs and public upload of this lab.

Phase: **publicly published; local and initial hosted checks passed**. All 31 real authentication cases passed and their identities, nonce linkage, intended selectors and hashes were audited. Nine real replay outcomes match earlier measured passes. Final-source baseline/rotation pass; two actual aggregate reports exactly correlate three exclusive-window messages (1790999960–1791000006 UTC). Twenty-six offline tests pass; Bandit 1.9.4 zero findings. Full final three-guest isolation gate and all six local connectivity expectations pass.

Review resolutions: verified queue/run cleanup ledger, actual selector DNS/signature checks, failed rotation exit, shared pre-mutation readiness gates, bounded actual reads, report header/time validation, complete SMTP identity assertions, current exact queue logs and seal after successful restoration. Separate SPF-only/DKIM-only alignment controls added. See docs/REVIEW.md for concrete findings and limitations. This is Codex self-review; independent human security review remains recommended before publication.

Runtime: Windows 11 Home, VirtualBox 7.2.6r172322, i7-11800H/64 GiB. Three owned Debian 13.7 guests remain running on isolated PEAL-experiment plus restricted host-only management. NIC3–8 disabled; no NAT/bridge/default route/forwarding; guest IPv6 disabled. Private VM/SSH/signing material remains ignored. Guest package revisions accompany evidence. Preserve unrelated triage-toolkit working-copy changes; only its offline parser was reused.

Active core bugs: none known from the executed checks. Failed/partial attempts remain preserved. Run tools serially; after host suspension repair owned guest clocks with sync_clock, then require the full gate. SSH loss can block restoration, leaving an unsealed attempt that requires recovery before another submission. Keep at least 8 GiB host disk free.

Next local use: README and REVIEW_HANDOFF.md provide commands; use fresh outputs and inspect raw text/JSON only. Local review commit is on codex/phishing-email-auth-lab; use git rev-parse HEAD and git status --short for current identity. The October 3 portfolio review updated Obsidian with linked codebase/review notes; raw evidence remains in this repository.

Publication: https://github.com/jfrance167/phishing-investigation-email-auth-lab is public. Initial upload bd4f431 passed hosted Python/Bandit, PowerShell, CodeQL and Dependabot checks; code-scanning alerts were zero. Secret scanning/push protection, dependency security updates, private vulnerability reporting and read-only default workflow permissions are enabled. Branch protection is being finalized to require offline, powershell and python checks with no force pushes/deletion. The earlier automatic approval block was resolved by Jake's explicit public payload/visibility approval; the original audit records preserve that history.

Verified limits: ISO signed-checksum signature not checked; legacy DMARC/report behavior and separate same-day adapter; no full transitive CVE/XSD conformance audit; no ARC/SRS. No claim of production readiness or exhaustive vulnerability absence. Existing live lab results were not rerun during publication.

## Portfolio review follow-up — October 3, 2026

The security maintenance commit bounds evidence hashing/manifest input and directory traversal, and requires exact owned-VM identity plus an explicit fresh-login assertion before console recovery. The assertion is an operator confirmation, not automatic console-state verification. All 26 offline Python tests and the pure PowerShell ownership guard pass; all 116 historical evidence manifests verify unchanged. No VM recovery, live authentication scenario, firewall change or external service was run for this follow-up. Existing live results above remain historical. At this review checkpoint hosted CI and publication awaited approval; the later authorization below supersedes that prerequisite. Security-sensitive recovery logic still requires Jake’s manual review.

## Public publication authorization — October 3, 2026

Jake explicitly approved review/merge of the 23 portfolio remediation PRs followed by public GitHub upload of this lab. The preceding discussion identified the full evidence/history payload and visibility. This resolves the earlier user-approval prerequisite; no remote upload has yet occurred at this checkpoint. No new live lab action is authorized by this publication step.
