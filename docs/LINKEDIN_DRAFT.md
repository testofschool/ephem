# LinkedIn draft — zero profile

Draft only. Publish after reviewing the matching source and evidence. The public
alpha's earlier results and this branch's new results are distinct.

---

What if the server never received your plaintext in the first place?

I wanted to build a system where a compromised request had nothing useful to keep.

So I started with disposable workers: one request, a fresh restricted process, private scratch space, and cleanup before the response leaves.

Then I wrote the test I least wanted to pass.

“Read this synthetic secret. Return it. Exit normally.”

It worked.

The process disappeared afterward. The secret was already in the response.

That result changed what I built next.

1) Remove ambient secrets from the worker.

EPHEM now has an exact root-filesystem policy. Extra file? Changed executable? Symlink? Reject the launch. The gate checks again before every request.

With the same worker binary and the same request, the earlier secret-reading test went from returning the synthetic secret to rejecting execution. Public echo still worked.

A hash cannot decide whether an approved program contains a secret. The root must still come from reviewed inputs. That boundary is explicit.

2) Keep the decryption key on the client.

I added a deliberately narrow workload: a one-shot encrypted transfer relay.

The client encrypts locally. The server receives ciphertext. A fresh EPHEM worker handles that ciphertext. The relay retains a bounded object in RAM until one retrieval or expiry.

Decryption happens back on the client. There is no server decryption API.

This changes the data the server gets to hold. It does not make arbitrary plaintext applications confidential by wrapping them.

3) Test across the machine boundary.

A trusted Mac client and a separate Linux VM completed the real round trip. The key stayed on the Mac.

Eight simultaneous retrievals produced one successful claim. A second retrieval failed. Expired objects disappeared from the service, and a restarted relay restored none.

I also streamed a bounded sample of the owned relay's writable private memory back to the client. Across 371,998,720 scanned bytes, that run's synthetic plaintext and key had zero matches. The search needles stayed on the client.

That is one reproducible observation, with its limits published. It is not a physical-erasure certificate.

The current record includes 26 root-policy probes, 32 client/relay/store tests, and nine separate-client integration probes passing. The initial failed attempts are retained too.

The kernel and control plane still need patches. Independent security review is still ahead. A compromised server can still expose ciphertext and metadata, or refuse service.

But this is the direction I want to make practical:

Give a compromised request less authority, less history, and fewer secrets to reach.

The new profile is on an experimental branch. Source, threat boundaries, tests and raw evidence:
https://github.com/testofschool/ephem/tree/zero-secret-profile

If you operate a secret-free offline worker or need a short-lived encrypted handoff, which boundary would you try to break first?

#OpenSource #SecurityEngineering #Linux #Encryption

---

Evidence for the new claims:

- [Root replay: 26 probes](../evidence/zero/root-replay-v2.json)
- [Node tests: 32 tests](../evidence/zero/node-linux-v3.log)
- [Separate client run: nine probes and bounded memory observation](../evidence/zero/live-client-v3.json)
- [Installed-server identity and cleanup](../evidence/zero/server-live-client-v3.json)
- [Scope, assumptions and reproduction](ZERO_PROFILE.md)

Suggested image: [existing EPHEM illustration](../assets/ephem-hero.png). It is a
visual metaphor; it is not evidence of secret erasure.
