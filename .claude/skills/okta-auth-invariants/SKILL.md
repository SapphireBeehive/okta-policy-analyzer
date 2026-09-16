---
name: okta-auth-invariants
description: Investigate Okta authentication policies with formal verification. Use when someone asks who can sign in to an Okta app and how (MFA, phishing-resistant, password only), wants to prove or check a plain-English security invariant about Okta sign-on policies ("contractors can only reach Salesforce from the VPN", "admins always need phishing-resistant MFA"), wants shadowed/dead rules, DENY bypasses, weak catch-alls or enrollment lock-outs found, or wants two policy snapshots compared. Turns the invariant into a solver-checked assertion and reports PROVED (with assumptions) or a concrete counterexample.
---

# Okta authentication-policy invariants

You have `okta-policy-analyzer`, a tool that encodes every Okta Identity Engine authentication policy, global
session policy and enrollment policy into the z3 SMT solver. Anything it reports is *proved over all users and
contexts* (every group combination, network zone, device state, risk level), not sampled. Use it to answer a
CorpSec engineer's question about who can do what form of authentication, or to prove/refute an invariant they
state in plain English.

## Workflow

1. **Get a snapshot.** Look for an existing snapshot directory (contains `manifest.json` and `policies.json`) or
   `.json` snapshot in the repo or the path the person gives you. If none exists and an Okta API token is
   available in the environment, fetch one (read-only; needs `okta.policies.read okta.apps.read okta.groups.read
   okta.networkZones.read okta.deviceAssurance.read okta.authenticators.read okta.userTypes.read okta.idps.read`):
   ```bash
   okta-policy-analyzer fetch --org https://ORG.okta.com -o snapshots/ORG      # token in $OKTA_API_TOKEN
   ```
   Never invent policy data. If there is no snapshot and no token, say so and stop.
2. **Orient yourself** (once per snapshot): `okta-policy-analyzer analyze SNAPSHOT --no-cubes` prints findings,
   the per-app outcome tables ("who can obtain each form of authentication") and the global session policies.
   `okta-policy-analyzer who SNAPSHOT --app "APP" --max-strength ONE_FA_KNOWLEDGE` answers "who gets into APP
   with a password only". Group, app and zone names in later commands must match this output exactly
   (case-insensitive).
3. **Turn the person's sentence into an invariant.** Restate it in the controlled English below (see the
   phrasebook), keeping their intent, then run:
   ```bash
   okta-policy-analyzer check SNAPSHOT "Contractors can only reach Salesforce from the Corporate Network or VPN"
   okta-policy-analyzer check SNAPSHOT --file invariants.txt            # one sentence per line, # comments
   okta-policy-analyzer check SNAPSHOT "..." --yaml-out invariants.yaml  # export the formal assertions
   ```
   Exit codes: 0 all proved/vacuous, 1 a counterexample exists, 2 a sentence could not be read.
   The tool prints the **reading** (exactly what was proved) first. Always show the reading to the person and
   confirm it matches what they meant; the notes flag interpretation choices ("'with only a password' read
   literally: …"). If the sentence is UNPARSED, rephrase using the phrasebook or write the assertion YAML by
   hand (schema in the README) and run `okta-policy-analyzer verify SNAPSHOT --assertions FILE`.
4. **Report the verdict** in this shape:
   - **PROVED** — say "holds for every user and every context", then list the modelling assumptions the proof
     relies on (printed by the tool; e.g. "a managed device is always a registered device", opaque expression
     fragments). These are the only ways the proof could be wrong.
   - **VIOLATED** — give the counterexample as a story: which population (the *who* lines), in which context, is
     decided by which rule, with what outcome. Then explain *why* using the analysis findings for that policy
     (`analyze` output: `deny-bypassed`, `downgrade-path`, `shadowed-rule`, `weak-catch-all`,
     `unenrollable-requirement`), and quote the tool's *fix hint* when present. Offer the concrete change
     (move a DENY above an ALLOW, narrow a rule, strengthen a catch-all). You can replay a concrete world with
     `okta-policy-analyzer explain SNAPSHOT --group G --zone Z --managed --platform MACOS`.
   - **VACUOUS** — the premise matches nobody (usually a misspelled group/zone name); fix the name and rerun.
5. **Be honest about the model.** Universal claims that are PROVED hold in the real org (the encoding
   over-approximates reality). Existential results ("someone can get in with a password") are *possible*: the
   witness may rely on a group combination that no real user has, or on an uninterpreted expression. Say so,
   and suggest `okta-policy-analyzer simulate-validate` against the live org when certainty matters.

## Phrasebook (controlled English the `check` command understands)

The complete grammar with a table per clause is in `docs/invariants.md`; read it when a sentence is UNPARSED.

Subjects: `Everyone` · `Nobody` · `<Group name>` · `members of <Group>` · `<Group> or <Group>` · `users who are
not in <Group>` · `Only <Group> can …` · `users whose department is Finance` · a user login.
Context: `from <Zone>` · `from outside <Zone> or <Zone>` · `unless they are on <Zone>` · `from the internet` ·
`on an unmanaged device` · `on a managed device` · `on an unregistered device` · `on macOS/Windows/iOS/Android` ·
`on a device that passes <Device assurance policy>` · `at high risk` / `at medium risk` · `of user type contractor`.
Objects: `access/reach/sign in to <App label>` · `<App> or <App>` · `any app` · `apps governed by <Policy>`.
Requirements: `must be denied` · `cannot access` · `must use MFA` · `must use phishing-resistant MFA` ·
`must use hardware-protected MFA` · `cannot … with only a password` · `must not be able to sign in without a
password` · `must always enter a password` · `must be handled by rule 'X'` · `rule 'X' must never apply` ·
`can only … from <Zone>`. Add `even after the global session policy` to judge the combined requirement.

Worked examples:
- "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console" → for every admin in every
  context the deciding rule requires phishing-resistant 2FA (DENY also counts as satisfying).
- "Nobody can access any app with only a password" → for every user, every context, every app: the weakest
  accepted authentication is stronger than password-only.
- "Contractors can only reach Salesforce from the Corporate Network or VPN" → contractors outside both zones must
  hit a DENY rule.

## When the human wants it fixed

Switch to the `okta-policy-remediation` skill: `okta-policy-analyzer propose SNAPSHOT "<sentence>" --plan-out
plan.json` synthesises the rule change, proves it in the model and shows the impact; nothing is written to the
org without `apply --yes` after the human has seen the dry-run.

## Interpreting strength labels

DENY < 1FA knowledge (password only) < 1FA possession (email/SMS/OTP alone) < 1FA phishing-resistant
(FIDO2/FastPass alone) < 2FA (any two factor types) < 2FA phishing-resistant < 2FA phishing-resistant +
hardware-protected. A rule's strength is its *weakest* accepted path. "Unsatisfiable ALLOW" means the rule
allows on paper but no enabled authenticator can satisfy it (an effective lock-out).

## Other commands you may need

- `okta-policy-analyzer serve SNAPSHOT --invariants FILE` — local web UI to author invariants and browse
  policies, principals and violations; `--export page.html` for a read-only page.
- `okta-policy-analyzer analyze SNAPSHOT --format markdown -o report.md` — full report for the person.
- `okta-policy-analyzer diff OLD NEW` — what a policy change did: per app EQUIVALENT / MORE_PERMISSIVE /
  LESS_PERMISSIVE / INCOMPARABLE, with exactly who gained or lost access.
- `okta-policy-analyzer export-tla SNAPSHOT -o tla --run-tlc tla2tools.jar` — independent TLC check of the same
  invariants when a second formal backend is wanted.
- `docs/semantics.md` lists every Okta behaviour the model relies on with its source; cite it when asked "why do
  you believe that".
