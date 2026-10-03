# Learning

- SPF evaluates the connecting IP against the envelope identity; the visible From identity is separate.
- DKIM validates a signature and signing domain. DMARC passes if either passing SPF or passing DKIM aligns with visible From; broken DKIM with aligned passing SPF can still pass DMARC.
- Authentication does not establish benign intent. Lookalike-domain mail can authenticate successfully.
- Policy publication, authentication result, alignment and actual delivery/hold/rejection are separate evidence fields.
- Header order and a recognizable Authentication-Results authserv-id are attacker-copyable. Trust requires a controlled receiver path and independent evidence.
- Local worker draft retained under .private/local-draft.txt. Review corrected ambiguous alignment/provenance questions; no worker output was treated as a security decision or executed code.
- Correctly configured policy still needs an available MTA action. A quarantine symbol initially delivered; registering the action made the real hold observable.
- DNS TXT supports adjacent strings, each at most 255 octets. Windows newline translation can also invalidate a zone even when message authentication code is correct; regression tests catch that boundary.
- A private suffix is absent from public suffix data. Private alignment experiments must define the lab suffix instead of assuming organizational-domain behavior.
- Key retirement is not instant: old signatures passed with a warm resolver cache and failed after a cold-cache restart. Preserve TTL and cache state alongside verdicts.
- Upstream reporting dates select data keys separately from metadata bounds. Verify report timestamps against actual message collection; counts alone can conceal a misleading time range.
- Host suspension paused guest clocks despite VMs resuming. Recovery uses host UTC on owned guests and a fresh gate, never rewriting old evidence.
- The second local README draft incorrectly described selector overlap as a strict-policy bypass. Raw draft retained privately; documentation was corrected from measured evidence. Local worker restarted after initial loopback refusal; no remote/paid fallback used.

- Reviewed evidence can still support an unsafe operation if authorization relies on copyable headers. Link the exact queue and fresh nonce to its controlled collection before cleanup.
- A verdict is not enough: independently check SMTP identities and the actual signing selector, and exclude stale or substring queue logs.
- Completion includes cleanup. Preserve a failed restoration as an unsealed attempt instead of presenting it as a completed run.
- The local review-note draft incorrectly claimed guarantees and header authenticity. Its raw text remains private; reviewed corrections explain limited provenance and DKIM signing identity without those claims.
