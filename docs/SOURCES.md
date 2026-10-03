# Source selection, licensing and dependency review

Sources inspected October 1–2, 2026. Connected GitHub access was used for upstream source/release
inspection; a later connector transport failure was handled with official documentation and direct
GitHub tag APIs. This is a scoped source assessment, not an exhaustive vulnerability audit.

| Component | Fit and evidence | Licensing / decision |
|---|---|---|
| [Rspamd](https://github.com/rspamd/rspamd/tree/4.2.1) | Actual SPF/DMARC Lua, DKIM integration, milter header/transport and report code; release 4.2.1, test/workflow structure inspected. Local skipping, suffix list, SPF budget and quarantine defaults required measured overrides. | Mixed licenses, including Apache-2.0 and BSD-family components; exact packaged notices in evidence/licenses/rspamd-copyright.txt. Adopt signed upstream package; no crypto implementation. |
| [Mailpit](https://github.com/axllent/mailpit/releases/tag/v1.31.3) | Capture-only SMTP/API, release asset digest, runtime remote-content/version options, source go.mod/license/workflow inspection. Native version subcommand attempted update lookup, so omitted; service disables checks. | MIT upstream; retain attribution. Adopt hash-verified binary, loopback only. Full transitive Go dependency audit not performed. |
| [Postfix](https://www.postfix.org/) | Established MTA, milter/transport path and real hold queue; packaged 3.10.13 exercised. | Dual EPL-2.0/IPL-1.0; Debian copyright exported. Adopt package, not a fork. |
| [BIND](https://www.isc.org/bind/) | Authoritative private zone, recursion disabled, named-checkzone/config checks, reproducible DNS faults. | Mainly MPL-2.0 with bundled component licenses; packaged notices exported. |
| [Redis](https://github.com/redis/redis) | Rspamd reporting storage; fixed loopback binding, pre-consumption RDB export. | Installed Redis 8 notices offer RSALv2, SSPLv1 or AGPLv3. Do not describe this package as wholly BSD. Private VM artifacts are not distributed by this MIT code repository. |
| [Swaks](https://www.jetmore.org/john/code/swaks/) | Exact SMTP envelopes/source bind, transcripts and controlled synthetic submissions. | GPL-2.0-or-later in installed notices; adopted tool, not copied into lab source. |
| Existing automated-phishing-triage-toolkit | Inspected parser/tests; 13 tests passed against its working copy, which has unrelated changes. HEAD 0bb343c8b46f3497131d535884a8fe4471089aef is not the full working-copy identity. Adapter source SHA-256 is c498af88f7b85c1befbff3f085302b8fbec5e6d5f5e04e1d012154cfcac9dc47. | MIT. Reuse the explicitly reviewed parser offline, label results as claims, never enrich or auto-promote its heuristic verdict. Original repository unchanged. |

Recommend **adopt** established services and **build** small orchestration/evidence adapters. A full mail
platform adds services and public-facing assumptions unnecessary for this lab. No fork was required.
Source history/releases, real configuration and tests are useful evidence; popularity is not a safety
proof. No comprehensive Scorecard, CVE or all-transitive-dependency assessment was completed.

Debian packages were authenticated through signed apt repositories. Rspamd repository-key SHA-256
was checked before dearmoring; package/key metadata is preserved in the guests. Debian ISO integrity
was checked against official HTTPS SHA256SUMS; its signature was not independently verified. Mailpit
binary was checked against the official release asset digest. Exact hashes are in setup scripts.

Action v5 checkout, v6 setup-python and v4 CodeQL immutable commit IDs were resolved again through
official GitHub ref/tag APIs on October 2. Minimum permissions and disabled checkout credential
persistence are configured. These pins do not prove all action dependencies safe. Bandit 1.9.4 is
version-pinned for CI; a full hashed transitive development lockfile is not provided. Runtime Python
uses standard library facilities with explicit bounds, reviewed process arguments and no HTTP enrichment.

Useful primary documentation: [Rspamd DMARC](https://docs.rspamd.com/modules/dmarc/),
[actions](https://docs.rspamd.com/configuration/metrics/),
[milter headers](https://docs.rspamd.com/modules/milter_headers/),
[Mailpit runtime options](https://mailpit.axllent.org/docs/configuration/runtime-options/),
[RFC 9989](https://datatracker.ietf.org/doc/html/rfc9989),
[RFC 9990](https://datatracker.ietf.org/doc/html/rfc9990).
