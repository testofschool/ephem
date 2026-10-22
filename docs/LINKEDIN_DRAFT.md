# LinkedIn launch draft — English

Status: draft only. No LinkedIn post has been published. The text below uses the
verified ARM64 experiment; GitHub CI status remains separately inspectable.

---

What if a compromised request didn't get a second lifetime?

I started with a stubborn question:

“Why does an application keep yesterday's risk alive after today's request is already over?”

That question became EPHEM, an experimental open-source Linux runtime.

One request. One disposable worker.

1) Give the request less to keep.

EPHEM starts a fresh restricted worker for each request. Its application filesystem is read-only. Its scratch space belongs to that request. Direct networking is denied.

2) Finish the cleanup before releasing the result.

Output stays staged until execution and teardown checks pass. A crash, forbidden syscall, timeout, output overflow or cgroup OOM discards that staged output.

On a real Linux VM, the current build passed 12 lifecycle tests. Fifty sequential requests used fifty distinct workers. An existing 963-byte PHP receiver handled four uploads without a source-code change.

Those are small, reproducible results. They are what we've actually measured.

3) Publish the uncomfortable test, too.

I added a worker that reads a synthetic secret and returns it normally.

It succeeds.

Because destroying a process afterward cannot undo data it was allowed to return. Clean exit is not proof of safe computation. That boundary belongs in the README, alongside the demo.

This isn't a world-first isolation primitive. Groundhog, nsjail, gVisor and others have already done important work here.

The contribution I'm working on is making a strict request lifetime practical for compatible existing CGI/CLI workloads—with restrictive defaults and evidence you can inspect.

No “unhackable” claim. No promise that patches disappear. The privileged control plane still needs hardening and external review.

But I want to keep pushing this question:

How much damage can we remove simply by refusing to give a request a second lifetime?

Code, threat model, raw tests and the counterexample:
https://github.com/testofschool/ephem

If you maintain an offline parser or a read-only CGI handler, I'd be interested in the first compatibility boundary you would test.

#OpenSource #SecurityEngineering #Linux #Sandboxing

---

Suggested image: [`assets/ephem-hero.png`](../assets/ephem-hero.png).
Evidence: [`evidence/RESULTS.md`](../evidence/RESULTS.md).
Prior art: [`docs/PRIOR_ART.md`](PRIOR_ART.md).

Do not add world-first, zero-deployment, patch-free or physically-unhackable claims.
