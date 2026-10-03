# Reusable tools and failure contracts

Run from repository root, serially. Reviewed Windows executable paths and pinned host keys are
required; private key/capture paths are ignored. Each tool rejects existing output directories/files
except build_index, which regenerates its derived index. Scripts do not add an Internet route on failure.

| Tool | Inputs / prerequisite | Output / verification |
|---|---|---|
| Get-Preflight.ps1 | `-Output FRESH.json`; local CIM/VirtualBox access | Read-only host capacity/interfaces/routing inventory |
| New-LabVM.ps1 | `-Role sender/receiver/relay`, verified private ISO and public key, disk floor | Named VM; provisioning NAT only; refuses existing names |
| provision-packages.sh | Owned trixie guest, role, temporary controlled provisioning | Signed selected packages, key/package metadata; locks passwords |
| configure-network.sh + Set-IsolatedNICs.ps1 | Matching marker/owned powered-off VM | Static routes, nftables, no NAT/bridge; requires subsequent runtime gate |
| configure-mail.sh / configure-dns-mailpit.sh / configure-relay.sh | Owned role, reviewed packages, receiver public DNS/binary inputs | Effective service config and config checks; keys stay guest-local |
| Test-LabReady.ps1 | `-OutputDirectory FRESH -IncludeRelay` | Full NIC/path/host forwarding, routes/IPv6, normalized firewall, sockets/config and clock gate |
| guest_connectivity.py | Sender with isolation gate passed | Six fixed local permitted/denied connection results; no third-party probes |
| lab.py | Fixed ID in matrix, `--output FRESH`; gate runs automatically | Original/submitted/post receiver copies, DNS, envelopes/transcripts, fresh run/queue record, logs, assertions and hashes |
| rotation.py | `python -m tools.rotation --output FRESH` | Disposable lab2 overlap and warm/cold retirement; restores DNS/selector in finally; gate before mutation; fails on any of four outcome mismatches |
| reports.py | `--output FRESH [--begin ACTUAL_EPOCH]`; exclusive controlled window | Readiness gate, RDB backup, delivered report MIME/XML, source adapter where used, hashes. Generator consumes own keys |
| correlate_reports.py | `--window PATH --reports PATH --output FRESH.json` | Exact counts/IP/auth/disposition/timestamp assertion for exact-alignment control windows |
| toolkit_adapter.py | `--toolkit reviewed/phishing_triage.py --sha256 HASH --bundle HASHED_CASE --output FRESH.json` | Offline claim parser + separate receiver evidence. Import executes reviewed module; never enrichs |
| reset_replay.py | `--output FRESH`; fixed owned guests and intact bundles | Verified role/queue/scenario/nonce ledger, exported queues/hash, byte recheck and individual removal, semantic reset, nine-case replay assertions |
| compare_replay.py | `--replay HASHED_REPLAY --output FRESH.json`; earlier measured passes | Compares all nine actual semantic outcomes with earlier queue-correlated runs, excluding signatures/times/queue IDs |
| sync_clock.py | `--output FRESH`; owned guests after host suspension | Before/after clock evidence; host UTC only, no NTP; rerun gate |
| evidence.py | `claims/receiver/manifest/verify PATH` | Bounded parser, source-explicit summary, hashes/file-set verification |
| build_index.py | Completed existing evidence, no active writers | Derived passing-ID index; refuses changed completed bundles |
| check_secrets.py | Git available; reviewed staged/tracked files | Count and paths only for potential findings; values never printed; reads local reachable history |

Failures are visible exceptions/nonzero exits; partially collected directories remain incomplete.
Do not reuse them as passing evidence or overwrite them. Policy restoration is in finally, but a host
or SSH outage can prevent restoration: check clocks, gate and run reset before resuming. No automatic
retries are made for scenario submissions, preventing duplicate ambiguous delivery. A relay reinjection
retry with the same run nonce refuses to overwrite existing evidence and remains queued for review.

Firewall textual presentation is pinned to the reviewed installed nft output, excluding dynamic counters.
A package/presentation change intentionally blocks until the entire policy is reviewed and the fixture
is updated. The reset does not claim a factory-clean disk or empty Mailpit; retained captures support audits.

The shared `lab.ready(output, include_relay=False)` runs the same strict gate for cases, rotation, reset and reports. `queue_ledger(root)` consumes intact controlled bundles; `authorized_queue(role, qid, raw, ledger)` is a pure decision with no deletion. Unknown/duplicate-header/nonced-less records are denied. Case manifests are created only after successful restoration. Report correlation requires positive integer counts, matching header identity and ordered integer time bounds. Tests in `tests/test_review_regressions.py` exercise these failure contracts.
