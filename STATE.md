# Lab state

Authorized October 1, 2026: implement, debug, test and document the supplied Tier 3 scope locally. No publication, remote creation, push or merge.

Phase: local review package. **Working core verified: 26 authentication scenarios, reports, and nine-case reset/replay pass.** Publication and independent manual review remain pending.

Verified host: Windows 11 Home 10.0.26200; Intel i7-11800H, 8 cores/16 threads; virtualization and SLAT enabled; 64 GiB RAM (about 44 GiB available); VirtualBox 7.2.6r172322; no running VMs at inventory; about 19 GiB free C: disk. WSL docker-desktop exists but is stopped and is not the lab runtime.

Existing toolkit: 13 tests passed against the current working copy. It has unrelated uncommitted changes; preserve them. HEAD 0bb343c8b46f3497131d535884a8fe4471089aef is not the complete tested working-copy identity.

Verified: official Debian 13.7.0 installer HTTPS SHA-256; all three owned guests isolated; IPv4/IPv6, full normalized firewall structure and VM ownership gates; six lab-local permitted/denied connection checks; private/local auth evaluation; actual Postfix holds/rejection; two relay paths; forgery and lookalike cases; selector overlap/retirement warm/cold caches. 26 passing IDs in evidence/INDEX.json. Nine-case reset/replay-02 passes; real aggregate reports correlate to nine-case replay and three-case exclusive window. 12 offline tests pass; Bandit 1.9.4 zero findings. Source/header controls still require independent manual review.

Resolved: Windows DNS newline handling, bounded TXT strings, explicit .test suffix/alignment policy, SPF request budget, quarantine action registration, selected module set, fresh run nonce, literal filename/postcat/Swaks arguments, strict ownership/firewall gates. Failed/partial attempts retained. Host suspend caused management timeouts and stale guest clocks; recovery captured without changing old evidence.

Next: inspect REVIEW_HANDOFF.md and perform independent manual review. Run tools serially; after suspension run sync_clock and the full gate. Stop sending if any gate fails. VM/capture/key files remain private and local.

Pending external actions: no remote created, push, deployment or merge. Prepared immutable-pinned GitHub workflows have not run; visibility/eligibility, CodeQL, protections, reviews, secret scanning/push protection and Dependabot require publication scope/approval. Known limits: HTTPS ISO checksum signature not verified, legacy DMARC/report format, documented separate current-window report adapter, no full transitive dependency/CVE audit, no ARC/SRS. No active core test failure.
