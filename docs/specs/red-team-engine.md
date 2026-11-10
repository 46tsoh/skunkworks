# Red-team engine (autonomous, scope-gated)

Status: **design + authorization foundation** (stage 1 in progress).

Aegis's second use case: autonomous red-teaming for OSAI-style and general
hacking competitions (CTFs). Where the analysis engines *find and reason about*
weaknesses, the red-team engine *acts* on them — it chains recon → exploit →
verify against a target it is **explicitly authorized** to attack, to produce
proof (a confirmed vulnerability, a captured flag).

This is offensive capability. The whole design is built around one idea: **every
offensive action is refused unless the target is inside a declared engagement
scope.** Capability is staged so the authorization and audit layer is proven
before the higher-blast-radius stages (post-exploitation, lateral movement) are
built on top of it.

## Authorization model (the load-bearing control)

Two gates, both required for any offensive action:

1. `--authorized` — the operator asserts they are permitted to test (same gate
   as `aegis scan`).
2. **An engagement scope file** (`--scope <path>`) — a declarative allowlist of
   exactly what may be touched. Every target an action would reach is checked
   against it; anything not in scope is **refused before the action runs**, and
   the refusal is logged. There is no "attack everything" mode.

### Scope file format (YAML/JSON)

```yaml
engagement: "hackthebox-season-7"      # free-text label, recorded in the audit log
authorized_by: "operator"              # who authorized it (recorded)
expires: "2025-12-31T23:59:59Z"        # hard stop; actions refused after this
targets:
  hosts:                               # exact hostnames / IPs
    - 10.129.0.0/24                    # CIDR allowed for ranges you own/are assigned
    - target.htb
  urls:                                # exact URL prefixes for web targets
    - http://target.htb/
deny:                                  # explicit never-touch (wins over any allow)
  hosts: ["10.129.0.1"]                # e.g. the gateway
limits:
  max_hosts: 16                        # pivoting cannot exceed this many hosts
  allow_lateral: false                 # stage 3 switch; default off
  allow_post_exploit: false            # stage 2 switch; default off
```

Enforcement rules:

- **Default-deny.** An empty or missing scope file authorizes nothing.
- **Deny wins.** A host in `deny` is never actionable, even if an allow rule
  would match it.
- **CIDR membership**, not substring matching — `target.htb.evil.com` does not
  match `target.htb`, and `10.129.0.5` matches `10.129.0.0/24` only by real
  subnet membership.
- **Expiry is hard.** After `expires`, every offensive action is refused.
- **Stage switches are opt-in.** `allow_post_exploit` / `allow_lateral` default
  to false; the corresponding stages refuse to run until the operator sets them
  per engagement, so capability escalates deliberately, never by accident.
- Every action records `{engagement, target, in_scope, decision}` to the run's
  audit log, so an engagement is fully reconstructable.

## Staged capability roadmap

**Stage 1 — authorization + exploit→verify (this milestone).**
Scope module + gate + audit log, then a bounded loop: take a confirmed-class
finding from the scanners (SQLi / XSS / command or code injection / open
redirect), attempt a *single bounded* exploit against the in-scope target,
and **verify** the result (e.g. a boolean-SQLi oracle, a reflected marker, an
out-of-band callback the operator hosts). Stop at proof. No shell, no
persistence, no pivoting. This already solves most OSAI/CTF web challenges.

**Stage 2 — post-exploitation (gated by `allow_post_exploit`).**
On a verified foothold, run bounded read-only proof commands (retrieve a flag,
`id`, read a named file) within scope. No persistence, no destructive actions.

**Stage 3 — lateral movement (gated by `allow_lateral` + `max_hosts`).**
Pivot only to hosts already inside the scope file, never auto-expanding scope,
bounded by `max_hosts`. Built only after stages 1–2 and their audit trail are
proven.

## Hard boundaries (all stages)

- Never acts outside the engagement scope; scope is operator-declared data, never
  inferred from a page, a finding, or tool output.
- No destructive actions (no data deletion/corruption, no DoS/flooding), no
  persistence/backdoors, no credential exfiltration beyond in-scope proof, no
  detection-evasion tooling. The goal is proof, not damage.
- Local-only infrastructure and the Docker isolation model are unchanged; the
  only network egress is to in-scope targets.
- Fixture-first like every other capability: the loop is testable offline with
  recorded exploit/verify exchanges and no live target.
