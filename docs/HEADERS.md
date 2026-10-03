# Header examples and evidence trust

The S10 original includes these attacker-copyable claims:

```text
Authentication-Results: receiver.recipient.test; spf=pass; dkim=pass; dmarc=pass
Authentication-Results: conflicting.test; spf=fail; dkim=fail; dmarc=fail
Received: from trusted.test (trusted.test [10.77.0.10]) by receiver.recipient.test with ESMTP id FORGED
```

Matching the receiver name does not authenticate the first header. The .10 address in the forged
Received line does not establish the actual connection. In the preserved replay, controlled receiver
collection records .11, MAIL FROM analyst@sender.test, SPF fail, DKIM none and DMARC fail. Postfix
strips submitted Authentication-Results before Rspamd emits its own result. The misleading Received
line remains explicitly untrusted; the actual connection and queue ID come from logs/receiver API.

An ordinary signed message has `DKIM-Signature: ... d=sender.test; s=lab1; ...`. Those values are
claims until the receiver checks the signature against the published DNS key. Signature failure after
a body change does not force DMARC failure when passing aligned SPF remains (S05a).

`X-Lab-Scenario`, `X-Lab-Run` and Message-ID are correlation aids under the controlled runner, not
authentication mechanisms. The fresh run nonce prevents accidentally selecting an earlier record;
trusted collection and queue/socket/envelope correlation supply provenance.

`tools/toolkit_adapter.py` calls the reviewed existing toolkit's `parse_email` offline. Its compact
authentication summary is labeled a claim. In `evidence/toolkit-forged-header.json`, the toolkit
summarizes SPF as pass while the receiver independently observes fail. All conflicting submitted
headers remain visible. No enrichment or automatic heuristic verdict is promoted to trusted auth.
