# Reviewed local implementation handoff

Repository: **C:/Users/Jake/OneDrive - Alfred State College/Documents/New project/phishing-investigation-email-auth-lab**

Branch: **codex/phishing-email-auth-lab**. Implementation checkpoint:
**8193475f5ddde9d2e50ce0098f944ae43f066dfb**. This handoff is added in a subsequent local documentation
commit; use `git rev-parse HEAD` for its final revision and `git status --short` for current changes.
No remote repository, push, publication, merge or remote protection change was made. Ignored `.private`
contains VM disks, installer/evidence drafts, disposable keys and pinned host keys; do not publish it.

## Completed agent review, October 2–3, 2026

Jake authorized review and completion. Codex reviewed its own implementation and fixed the required findings; this is not independent human review. See [docs/REVIEW.md](docs/REVIEW.md) for findings, scope, five review dimensions and limitations. Reviewed pre-fix base: b272b952e217f5b37cd174e8f5c8ac0527a4b9fe. Use `git rev-parse HEAD` for the local review commit.

Latest evidence is `evidence/review-01`: all 31 real authentication cases audited, 9 actual replay comparisons passed, 21 offline tests passed, Bandit zero findings. Final-source S01 and all four rotation cases passed. Two real aggregate reports exactly cover three controlled messages in UTC range 1790999960–1791000006. Full three-guest gate and six fixed connectivity checks passed after restoration.

Reproduce the updated checks from repository root with fresh output paths:

```powershell
python -m unittest discover -s tests -v
python -m bandit -r tools
python -m tools.evidence verify evidence/review-01
python -m tools.compare_replay --replay evidence/review-01/reset-replay --output evidence/my-fresh-comparison.json
python -m tools.correlate_reports --window evidence/review-01/report-window --reports evidence/review-01/reports --output evidence/my-fresh-correlation.json
```

Reset removed only two verified held entries after preserved exports and byte rechecks. Unknown entries remain outside deletion authorization. Latest hold queue CE6C240114 is preserved in `review-01/reset-replay/S07q`; the exact post-reset state is in final-isolation. The older table below remains historical evidence (26 cases/12 tests at the previous checkpoint), not the latest review totals.

## Delivered scope

Three real Debian guests; isolated internal SMTP/DNS and restricted host-only SSH; signed local
authentication; 31 passing authentication scenarios covering all 12 authentication categories;
real aggregate reports/correlation covering category 13; real quarantine and rejection; separate
untrusted claims/trusted receiver collection; toolkit offline adapter; rotation/cache experiments;
guarded semantic reset and nine-case replay; two analyst capstones; reusable scripts and local checks;
prepared GitHub security workflows; attribution, threat model and learning records.

Deviations: private .test suffix and explicit child policies are required for this selected implementation.
SPF DNS request budget is explicitly 10 rather than default 30; it is not a full RFC lookup-term
conformance test. Current-window reports use a separate documented two-edit upstream Lua adapter;
the upstream daily command is unchanged. Reset retains captures/keys/Redis and unknown or unlinked queues,
rather than destroying VMs or wiping databases. No optional fourth DNS VM was needed.

## Runtime and entry points

VirtualBox 7.2.6r172322 on Windows 11 Home, i7-11800H/64 GiB RAM. Debian 13.7.0 guests:

| VM | RAM / CPU / dynamic disk | Internal / management |
|---|---|---|
| PEAL-sender | 1536 MiB / 2 / 6 GiB | 10.77.0.10 (+.11 unauthorized) / 192.168.56.50 |
| PEAL-receiver | 2048 MiB / 2 / 8 GiB | 10.77.0.20 / 192.168.56.51 |
| PEAL-relay | 1024 MiB / 1 / 6 GiB | 10.77.0.30 / 192.168.56.52 |

Experiment NIC2: `PEAL-experiment` internal network. NIC1 host-only existing adapter, SSH input only
from 192.168.56.1. Other NICs disabled. No host/guest forwarding/default route; guest IPv6 disabled.
Postfix 3.10.13-0+deb13u1; Rspamd 4.2.1-1~b7a16ae~trixie; BIND 1:9.20.29-1~deb13u1;
Redis 5:8.0.2-3+deb13u2; Swaks 20240103.0-2; Mailpit 1.31.3; Python 3.13; Bandit 1.9.4.
Exact package/config/time dumps accompany cases. Installed notices are in `evidence/licenses`.

Read `README.md`, `docs/THREAT_MODEL.md`, `docs/TOOLS.md`, then `tools/lab.py` and
`tools/guest_validate.py`. Setup/network/mail scripts are explicitly separated from experiment entry.

## Executed verification and evidence

Executed from the absolute repository above, with local administrative inventory/VirtualBox/SSH
access as required. All paths below resolve under that repository.

| Executed command | Result / evidence |
|---|---|
| `pwsh -NoProfile -File tools/Test-LabReady.ps1 -IncludeRelay -OutputDirectory evidence/final-isolation` | All three strict VM path/NIC, host forwarding, IPv4/6, normalized full firewall, socket/config and clock gates passed |
| Pinned sender SSH `python3 /opt/peal/guest_connectivity.py` | 6 fixed lab-local checks matched: receiver25/53 permitted; Mailpit1025/8025, host25 and receiver-management22 denied. `evidence/final-isolation/connectivity.json` |
| `python tools/lab.py S01 --output evidence/final-gate-baseline` | Final strict-gate SPF/DKIM/DMARC pass, delivered; full bundle hashed |
| `python tools/lab.py ID --output FRESH_CASE_DIRECTORY` for matrix IDs | 26 passing IDs across `evidence/INDEX.json`; expected values saved before each run. Early failures/partial runs retained, not counted |
| `python -m tools.rotation --output evidence/rotation-01` | Old/new selector overlap and warm/cold retirement: all four expected outcomes matched |
| `python -m tools.reset_replay --output evidence/reset-replay-02` | Completed evidence verified before reset; nine normalized outcomes matched. First interrupted reset attempt retained separately |
| `python -m tools.compare_replay --replay evidence/reset-replay-02 --output evidence/replay-comparison.json` | All nine actual outcomes match independently recorded earlier passes for source IP, SPF, DKIM, DMARC and disposition; signatures/timestamps/queue IDs intentionally differ |
| `python -m tools.reports --output evidence/reports-replay-01 --begin 1790997552` | Actual aggregate MIME/XML delivered locally; nine replay messages |
| `python -m tools.reports --output evidence/reports-controlled-final --begin 1790997683` | Two actual reports, three exclusive-window messages; window ends 1790997723 UTC |
| `python -m tools.correlate_reports --window evidence/reset-replay-02 --reports evidence/reports-replay-01 --output evidence/replay-report-correlation.json` | Exact nine-message counts/IPs/results/dispositions/time enclosure passed |
| `python -m tools.correlate_reports --window evidence/report-window-03 --reports evidence/reports-controlled-final --output evidence/report-correlation-final.json` | Exact three-message correlation passed |
| `python -m tools.toolkit_adapter --toolkit ../automated-phishing-triage-toolkit/phishing_triage.py --sha256 c498af88f7b85c1befbff3f085302b8fbec5e6d5f5e04e1d012154cfcac9dc47 --bundle evidence/matrix/S10-run4 --output evidence/toolkit-forged-header.json` | Existing parser reused offline; SPF pass claim differs from independently collected fail; claims remain explicitly untrusted |
| `python -m unittest discover -s tests -v` | 12 tests passed; `evidence/offline-tests-final.txt` |
| `python -m bandit -r tools -f json -o evidence/bandit-final.json` | Zero findings. Narrow explained exclusions for fixed subprocess calls, wildcard-bind rejection and bounded DTD-free UTF-8 XML require manual review; warnings about unmatched exclusions are not findings |
| `python -m tools.evidence verify evidence/reset-replay-02` (also rotation-01 and reports-controlled-final) | File-set/hash checks passed; build_index verified completed scenario bundles |
| PowerShell AST ParseFile on all tools/*.ps1 | Zero parse errors; no destructive script invocation used for syntax testing |
| `git diff --cached --check -- . ':!evidence'` | Source whitespace check passed. Raw evidence intentionally preserves CRLF/trailing bytes; global diff whitespace check flags those bytes and is not claimed clean |
| `python -m tools.check_secrets` before/after implementation commit | No high-confidence secret/private-artifact findings in tracked files/reachable local history; values withheld. Not a full secret-scanning guarantee |

Scenario evidence includes original/submitted copies, DNS configuration/answers, SMTP envelopes and
transcripts, receiver JSON/logs, delivered or held raw message where applicable, exact config/versions,
run nonce/time, expected/observed results and SHA-256 manifest. Rejected cases use SMTP/log evidence;
absence from Mailpit alone is not proof of rejection.

Actual held replay queue: **5D22F40137**. Rejected replay queue: **77175401A3**.
Forwarding capstone queue **31589401A3**, lookalike capstone queue **9267D401A3**.
Forgery original claims, stripped ingress and actual receiver fail are in `reset-replay-02/S10`.

## Risks, limitations and manual review

No active core assertion failure remains. Partial attempts remain visibly incomplete. A long host
suspension caused SSH timeouts and stale guest clocks; `clock-recovery-01` records repair to host UTC.
Rerun the full gate after suspension; tools never modify historical evidence timestamps. Last named
guests remain running and isolated; inspect actual state before reuse.

An earlier unmarked sender staging entry was retained/deferred by that historical reset. The current
reset exports every pending entry and requires verified queue/run linkage before deletion. Captures and reporting data remain retained by design. Runtime tools share guest paths and
must run serially. SSH loss can prevent finally restoration; recovery requires gate/reset before sending.
Report generator consumes its own data; keep RDB backups. The failed first report generation lacked
correct cross-domain authorization and consumed its keys, but its pre-generation RDB remains preserved.

Review authentication and ingress stripping settings, actual loaded module restrictions, strict path/NIC
ownership, remote shell command construction and input allowlists, relay retry behavior, XML bounds,
report source edits/licensing, and guarded queue reset. Root/host compromise invalidates provenance;
hashes cannot defend against a trusted administrator rewriting both evidence and manifests.

Debian checksum signature not independently verified; limited supply-chain/dependency assessment;
legacy pct/unnamespaced report format is not full RFC 9989/9990 support; no XSD interoperability test.
ARC, SRS, public-provider testing, external enrichment, malware and real victim data were not run.

## Minimal reproduction

1. Inspect this local checkpoint and current Git status; read raw evidence as text, never render HTML.
2. Verify hashes and compare expected/observed records. Inspect final-isolation and receiver hold/reject logs.
3. Inspect named VM state/NICs and private host keys. Start only these owned guests if stopped; after
   suspension run sync_clock to a fresh directory and rerun the full gate.
4. Run S01, S07q, S07x, S09f/S09m and S10/S11 to fresh directories. Run reset_replay for reproducibility.
5. For a new machine, follow docs/SETUP.md with fresh private keys and official verified artifacts.
   No private VM/image/key files are distributed in the Git repository.

## Pending external actions

Independent human/security review remains required. Prepared CodeQL/test/Bandit workflows have not
run on GitHub. After explicit publication approval, inspect visibility/default branch/CodeQL eligibility,
enable applicable code and secret scanning/push protection/Dependabot, configure reviews/checks without
weakening protections, run hosted checks and address findings. No remote settings were changed here.
The October 3 portfolio review updated the Obsidian codebase/review notes. Raw evidence remains in Git; no credentials or operational inventory were imported.

## Portfolio review follow-up — October 3, 2026

The security maintenance commit bounds evidence hashing/manifest input and directory traversal, and requires exact owned-VM identity plus an explicit fresh-login assertion before console recovery. The assertion is an operator confirmation, not automatic console-state verification. All 26 offline Python tests and the pure PowerShell ownership guard pass; all 116 historical evidence manifests verify unchanged. No VM recovery, live authentication scenario, firewall change or external service was run for this follow-up. Existing live results above remain historical. Hosted CI and publication remain blocked as described above. Security-sensitive recovery logic still requires Jake’s manual review.
