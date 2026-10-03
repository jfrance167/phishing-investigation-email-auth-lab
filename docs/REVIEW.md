# Completed local review

Reviewed October 2–3, 2026 (local client dates; raw timestamps remain UTC). Scope: the local lab implementation, its controlled scenario matrix, input boundaries, isolation gates, reset/replay and report verification. Reviewed base: b272b952e217f5b37cd174e8f5c8ac0527a4b9fe; fixes are in the subsequent local commit. This is Codex review of its own implementation, not independent human review. No remote or publication action was authorized or performed.

## Findings and resolutions

| Priority | Before | Fix and verification |
|---|---|---|
| P2 | Reset deletion trusted a copyable synthetic scenario header | Require verified collection linkage by role, queue ID, scenario and fresh nonce. Export bytes/hash/authorization first; recheck unchanged bytes before individual deletion. Unknown entries stay retained. Positive and negative offline tests; real hold exports/removals in review-01/reset-replay |
| P2 | Rotation captured lab1 DNS regardless of actual selector and could exit successfully on mismatched outcomes | Query actual selector; require signature d/s identity before staging removal; fail unless all four measured results match; preserve summary/restoration. Wrong-selector and failing-result regression tests plus live rotation |
| P2 | Delivery proof could match stale/reused or substring queue IDs | Require exact queue context and current receiver collection time; retain original log candidates separately. Stale-day and substring regression test plus real delivered/held/rejected runs |
| P2 | Verdict assertions did not require every actual SMTP identity | Compare socket IP, HELO, MAIL FROM, RCPT TO and parsed From independently. Mutation regression test and offline audit of all 31 real cases |
| P2 | Completion hashes could precede successful cleanup | Seal case only after DNS/signing restoration completes. Injected cleanup failure leaves observed evidence unsealed; new live runs retain restoration receipts |
| P2 | Reports and rotation lacked the shared pre-mutation readiness gate | Require owned-guest isolation gate before operation. Injected gate failures perform no remote mutations; real gates preserved |
| P2 | File-size precheck could permit a growing file to be read without a bound | Bound the actual open-stream read to 2 MiB + 1 and reject overflow; growing-file regression test |
| P2 | Report comparison omitted row header identity and ordering of time bounds | Require header identity equal to controlled policy domain, positive integer counts and ordered integer date range. Negative fixtures plus exact local report correlation |
| P2 | Combined alignment cases could conceal a broken individual mechanism | Add S02a and separate SPF-only/DKIM-only relaxed/strict controls S06a–d; all five real cases pass |

No unresolved required finding from this scoped review remains. P2 denotes consequential reliability/security evidence faults in this disposable lab, not a claim of exploitability in a public service. No dependency upgrade or cryptographic implementation was added.

## Review dimensions

Correctness: expected values precede submission; actual socket/envelope identities, queue/run linkage and delivery evidence are separate from header claims. Complete matrix and actual replay comparison checked.

Readability: named helpers isolate readiness, selector identity, queue provenance and current log selection. Comments explain trust/failure boundaries; the controlled CLI remains narrow. A broader library abstraction would add complexity without another use case.

Architecture: authentication stays in Postfix/Rspamd. Standard-library host tools collect evidence; queue ledger is pure authorization logic, separate from destructive calls. No toolkit modification or external enrichment.

Security: fixed owned guests, pinned SSH, allowlisted scenario/command fields, no host MIME rendering, bounded hostile XML/MIME parsing, queue export before deletion and fail-closed isolation gates reviewed. Explained Bandit exclusions still need human inspection. Root/host compromise or rewriting both records and manifests invalidates provenance.

Performance: bounded parser reads, small controlled matrix and serial operations are appropriate. Ledger integrity hashing revisits retained evidence and is intentionally slower than trusting headers. No scale or load-performance claim is made.

## Verification

Evidence root: [review-01](../evidence/review-01/). All 31 authentication cases passed; audit.json verifies complete actual identities, fresh nonce linkage, actual signature selectors and DNS capture. Nine real replay runs match earlier measured outcomes in replay-comparison.json. Twenty-one offline tests pass; Bandit 1.9.4 reports zero findings, with narrow documented exclusions rather than blanket suppression.

Final-source baseline/rotation, exact three-message/two-report correlation and three-guest isolation/connectivity results are recorded alongside the matrix. Original failed/partial attempts and prior verification are retained; no historical evidence is rewritten. Hash checks detect changes against a trusted manifest, not malicious replacement of both.

## Remaining limits

Independent human review of authentication settings, ingress stripping, root SSH commands, ownership/firewall gates, relay retries and queue/report evidence remains recommended before portfolio publication. Hosted CodeQL/CI and GitHub security eligibility/protections have not been executed; no remote exists. ISO signed checksum signature, full transitive CVE assessment, ARC/SRS and current-standard report/XSD conformance remain outside the verified scope. The README and handoff state these limits.
