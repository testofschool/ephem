# Changelog

## 0.2.0 — experimental

- Package the Linux request-isolation prototype as a standalone Apache-2.0 project.
- Require cgroup v2 admission before launcher execution, per-request resource
  budgets, OOM checking, and teardown before output release.
- Refuse active swap and piped core collectors; disable gate core dumping.
- Pin the expected gate identity before launcher setup to close an early-orphan
  race. Keep worker response fingerprints out of runtime logs.
- Publish reproducible lifecycle, resource and response-exfiltration controls,
  a threat model, prior-art comparison and a factual launch draft.

The earlier local PHP2Shell ingress mitigation and historical evidence remain
outside this standalone package. No vendor patch bypass or universal protection
claim is made.
