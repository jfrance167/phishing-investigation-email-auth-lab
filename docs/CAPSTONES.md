# Two analyst investigations

## Legitimate mail fails authentication: S09m

**Verdict:** legitimate synthetic mail altered by a lab mailing-list relay, with high confidence
inside this controlled experiment. Authentication failure alone does not demonstrate malicious intent.

Timeline: sender creates S09m and signs `d=sender.test; s=lab1`. Sender submits the preserved message
to relay .30. Relay exports `before.eml`, appends a harmless footer and exports `after.eml`, then
reinjects through its Postfix service. Receiver queue **31589401A3** observes connecting IP .30 and
MAIL FROM analyst@sender.test. SPF fails because .30 is not authorized. DKIM fails because the body
changed. DMARC fails; published p=none results in actual delivery to Mailpit, confirmed in receiver logs.
Exact UTC timestamp and run nonce are in `evidence/reset-replay-02/S09m/receiver.json` and `run.json`.

Trusted evidence: pinned receiver JSON and logs, relay before/after hashes, separate envelopes and
queue-correlated Mailpit export. Untrusted alone: visible From, Message-ID, Received chain and any
submitted Authentication-Results. The local experiment controls the sending identity; production
investigations cannot infer legitimacy solely from an apparent known address.

Alternatives: an unauthorized sender could spoof that envelope; missing/wrong DNS keys could also
break DKIM; a tampered collector could invent results. Here the prior valid signature, controlled
relay transformation, published key and successful unchanged-forwarding control S09f narrow the
cause to the footer plus forwarding source. No cryptographic bypass occurred.

Remediation: preserve signatures through forwarding, avoid modifying signed content, evaluate
mailing-list identity rewriting and appropriate forwarding controls separately. ARC/SRS were not
implemented or tested. Do not casually authorize all forwarders in SPF or disable DMARC. In a real
incident, confirm the legitimate business mail path out of band before changing enforcement.

## Deceptive mail passes authentication: S11

**Verdict:** intentionally deceptive but harmless synthetic impersonation, with high confidence
from the controlled scenario and content; authentication itself does not establish deception.

Timeline: sender uses display name “Campus Security Team” and analyst@lookalike.test with a fictional
urgent account-review request. Sender legitimately signs lookalike.test and connects as authorized
.10. Receiver queue **9267D401A3** finds SPF pass, DKIM pass and DMARC pass and delivers to Mailpit.
The inert `hxxps://portal[.]lookalike[.]test` link was never visited. Exact timing is in the S11 bundle.

Trusted evidence: actual .10 socket/envelope, published lookalike DNS key and policy, pinned receiver
record, SMTP transcript and delivery log. Untrusted for organizational identity: the display name,
message wording and asserted brand. Passing authentication establishes aligned control of the
lookalike sending domain, not affiliation with a school or benign intent.

Alternatives: a legitimate fictional service might use that display name; a compromised legitimate
domain can also authenticate malicious mail. This lab deliberately authored impersonation content;
a production analyst needs business context and separate reputation/ownership evidence. No external
reputation query or brand-owner lookup was performed.

Remediation: inspect the actual address/domain, verify unusual requests through a known channel,
apply impersonation/content controls independently of SPF/DKIM/DMARC, and avoid entering credentials.
The lesson is not to weaken authentication: combine authenticated identity with intent/context review.

## Evidence procedure

Verify `evidence/reset-replay-02/S09m` and `S11` using `python -m tools.evidence verify PATH`.
Read raw files as text, not HTML. Compare `expected.json`, `observed.json`, `receiver.json`,
`receiver-logs.txt`, `receiver-smtp.txt`, submitted and post-receiver copies. Hashes detect changed
files; the host/guest control plane and pinned collection are still assumed trustworthy.
