# Threat model

Assets: host/home/work networks, private keys, raw evidence, receiver verdicts and analyst understanding. Adversarial inputs are synthetic MIME, spoofed identities, misleading trace headers and forged authentication claims. Jake controls guests, DNS, messages and management keys.

| Threat | Control | Required proof |
|---|---|---|
| Boundary escape or accidental public SMTP | Internal experiment NIC, no NAT/bridge/default routes, IPv6 controls, default-drop guest firewall | Hypervisor inventory, both-family routes/firewall, host forwarding, permitted/denied lab-local connections |
| Forged evidence | Preserve submitted bytes; strip ingress authentication/trace claims as documented; correlate queue IDs, SMTP envelope and receiver logs | Forged-header case and out-of-band receiver artifact |
| Malicious MIME/content | Synthetic plain text/inert links, size bounds, no attachment execution or host HTML rendering; no remote reputation/fetch modules | Effective config, firewall counters, parser rejection tests |
| Management exposure | SSH key, guest management firewall only host .1, loopback service bindings, no IP forwarding | Socket list, nftables rules, NIC inventory |
| Private-key leakage | Disposable locally generated keys under ignored .private or guest restricted directory; no raw generated installer files in Git | Tracked-file and history secret checks |
| Misleading authentication conclusions | Separate claims, trusted results, alignment, policy and disposition | Semantic assertions and capstone alternative explanations |
| Reset destroys evidence | Hash/export evidence first; reset only fixed owned lab names and matching marker | Integrity check and reset/replay proof |

Guest root and the host are trusted control planes. Hash manifests detect changes against a retained baseline; they do not authenticate a compromised receiver or prove truth. No external mail delivery, credential collection, malware, public-provider testing, ARC or SRS in scope. Provisioning access is temporary and not an experiment-ready state.
