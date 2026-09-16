# okta-policy-analyzer

Formal verification of **Okta authentication policies**. The tool pulls every policy and rule from an Okta
Identity Engine org (or reads a saved snapshot), models *all* groups, users, network zones, device states and
risk levels symbolically, and uses the **z3 SMT solver** to answer, exactly and exhaustively:

> **Who can do what form of authentication, for which app?**

It also finds policy bugs (shadowed and dead rules, DENY rules pre-empted by earlier ALLOW rules, weak catch-all
rules, requirements no enrollable authenticator can satisfy), **proves or refutes invariants you state in plain
English** ("Contractors can only reach Salesforce from the Corporate Network or VPN"), **proposes the rule
change that makes a violated invariant hold and proves it before applying it**, checks YAML assertions, and
can export the same model to **TLA+** for TLC as an independent second backend.

Operating it with Claude: `CLAUDE.md` is the operating guide (setup for a tenant, checking, making rules
safely) and `.claude/skills/` holds the two playbooks; `scripts/setup.sh` installs and self-tests.

```
$ okta-policy-analyzer analyze tests/fixtures/acme

HIGH findings (7)
● DENY rule 'Contractors elsewhere denied' is pre-empted by earlier ALLOW rule(s) 'Managed device passwordless'
    policy: Standard apps policy · apps: GitHub, Salesforce
    who:  member of Contractors ∧ not member of Service Accounts
    when: device passes macOS secure ∧ device managed
    witness: ... (e.g. groups={Contractors}, zones={} (no zone), device=registered managed MACOS assurance={dap_macos_secure}, risk=LOW)
● Rule 'Finance phishing-resistant' requires authenticators some matched users cannot enroll
    who:  userType user ∧ not member of Contractors ∧ member of Finance
...
Standard apps policy  →  GitHub, Salesforce
┃ outcome                                ┃ rules                          ┃ who (in some context)                                    ┃
┃ DENY                                   ┃ Service accounts denied, ...   ┃ everyone, in every context                               ┃
┃ 1FA knowledge (password only)          ┃ Sales on mobile (custom expr.) ┃ user.department == 'Sales' ∧ member of Sales ∧ ...       ┃
┃ 2FA (any factor types)                 ┃ Contractors from corp/VPN, ... ┃ member of Contractors ∧ not member of Service Accounts   ┃
┃ 2FA phishing-resistant                 ┃ Managed device passwordless    ┃ not member of Service Accounts                           ┃
  weakest way in: 1FA knowledge (password only) — e.g. user.department == 'Sales' ∧ member of Sales ∧ ...
```

## How it works

1. **Ingest** (`okta/`): a read-only client pulls authentication, global session, enrollment and password
   policies with their rules, app→policy mappings, groups, group rules, network zones, device assurance
   policies, authenticators (+methods), user types, IdPs and optionally users. Everything is stored as a plain
   JSON snapshot (safe to commit; no secrets).
2. **Normalise** (`loader.py`, `model.py`): Okta JSON becomes an engine-independent IR. Rules are ordered
   exactly as Okta evaluates them (priority ascending, catch-all last); Okta's documented quirks are handled
   (object-shaped constraints, case-variant keys, Classic `factors` settings, priority ties, deleted groups).
3. **Encode** (`smt/`): every fact a rule can test is a z3 variable — one Boolean per group membership, per
   zone, per device assurance policy, per named user; enums for user type, platform, risk, auth context, IdP;
   interned literals for profile attributes referenced by expressions; a free Boolean for every expression
   fragment the tool cannot interpret (sound over-approximation). Domain axioms tie them together
   (managed ⇒ registered, assurance ⇒ platform, group rules ⇒ membership, blocklist zones never reach
   policy evaluation). A rule's *effective* match is `match_i ∧ ¬(match_1 ∨ … ∨ match_{i-1})`; global session
   and enrollment policies are selected by priority with Okta's fall-through semantics.
4. **Assurance** (`assurance.py`): a rule's verification method (1FA/2FA, knowledge/possession constraints,
   phishing-resistant / hardware / device-bound / user-verification flags, allowed and excluded methods, auth
   method chains) is expanded into the finite set of *authentication paths* the org's enabled authenticators
   can satisfy, and classified on a strength order from DENY to 2FA phishing-resistant + hardware.
5. **Analyse** (`analysis.py`): every result is a solver query. WHO descriptions are complete DNFs of prime
   implicants over group membership and attributes, obtained by quantifier elimination of the context and
   all-SAT with cube minimisation; witnesses are minimal partial assignments plus one concrete world.
6. **Check** (`assertions.py`): YAML assertions are ∀-claims; a violation comes back with a counterexample.
7. **Second opinion** (`tla.py`): the very same z3 formulas are translated into a TLA+ module whose `Init`
   picks a world non-deterministically; TLC's invariant violations are the witnesses. On the bundled fixture,
   TLC and z3 agree on the reachability of every rule and on every assertion.
8. **Reality check** (`okta/simulate.py`): sampled worlds are sent to Okta's policy simulation API and Okta's
   winning rule is compared with the encoder's.
9. **Diff** (`diff.py`): two snapshots are encoded in one universe and compared per app — `EQUIVALENT`,
   `MORE_PERMISSIVE`, `LESS_PERMISSIVE` or `INCOMPARABLE` — with the exact population that gained or lost
   access or whose required authentication got weaker, plus the structural rule changes behind it.

A reference interpreter (`interpreter.py`) evaluates one concrete world directly; differential tests sample
hundreds of random worlds and check that the encoder and the interpreter always pick the same rule.

## Install

```bash
pip install -e ".[dev]"      # Python 3.11+, z3-solver, pyyaml, rich, httpx
python -m pytest -q          # optional: export TLA2TOOLS_JAR=/path/to/tla2tools.jar to run the TLC cross-check
```

## Usage

```bash
# 1. Snapshot an org (SSWS API token or OAuth 2.0 bearer token; read-only scopes listed below)
export OKTA_API_TOKEN=00...
okta-policy-analyzer fetch --org https://acme.okta.com -o snapshots/acme            # add --with-users for concrete mode

# 2. Analyse: findings + who-can-do-what per app (text, markdown or json)
okta-policy-analyzer analyze snapshots/acme
okta-policy-analyzer analyze snapshots/acme --format markdown -o report.md --assertions policy-assertions.yaml
okta-policy-analyzer analyze snapshots/acme --format json --fail-on-high                 # CI gate
okta-policy-analyzer analyze snapshots/acme --format sarif -o okta.sarif                 # GitHub code scanning

# 3. Prove or refute plain-English invariants (exit 1 on a counterexample, 2 if a sentence cannot be read)
okta-policy-analyzer check snapshots/acme "Okta Administrators must use phishing-resistant MFA for the Okta Admin Console" \
                                         "Nobody can access any app with only a password"
okta-policy-analyzer check snapshots/acme --file corpsec-invariants.txt --yaml-out policy-assertions.yaml

# 3b. Verify YAML assertions (exit code 1 on violation)
okta-policy-analyzer verify snapshots/acme --assertions policy-assertions.yaml

# 3c. Make a rule: propose the change that fixes a violated invariant, proved in the model, then apply it
okta-policy-analyzer propose snapshots/acme "Only Finance can access Payroll (Workday)" --plan-out plan.json
okta-policy-analyzer apply plan.json --dry-run                       # exact API requests, nothing sent
okta-policy-analyzer apply plan.json --yes                           # writes plan.json.applied.json for rollback
okta-policy-analyzer rollback plan.json.applied.json --yes

# 4. Ask targeted questions
okta-policy-analyzer who snapshots/acme --app Salesforce --max-strength ONE_FA_KNOWLEDGE  # who gets in with a password only?
okta-policy-analyzer explain snapshots/acme --user alice@acme.com --zone VPN --managed --platform MACOS
okta-policy-analyzer explain snapshots/acme --group Finance --attr department=Finance --risk HIGH

# 5. Second backend: TLA+ / TLC
okta-policy-analyzer export-tla snapshots/acme -o tla --assertions policy-assertions.yaml --run-tlc tla2tools.jar --tlc-probes

# 6. Compare with Okta's own evaluator (needs API access)
okta-policy-analyzer simulate-validate snapshots/acme --app Salesforce --samples 50

# 7. Formal diff between two snapshots (CI gate for policy changes): who gained access, who got weaker auth
okta-policy-analyzer diff snapshots/acme-yesterday snapshots/acme --fail-on-more-permissive

# Large tenants: analyse policies in parallel and skip the joint who+context cubes
okta-policy-analyzer analyze snapshots/acme -j 4 --no-cubes
```

Read-only OAuth scopes for a full snapshot: `okta.policies.read okta.apps.read okta.groups.read
okta.networkZones.read okta.deviceAssurance.read okta.authenticators.read okta.userTypes.read okta.idps.read`
(+ `okta.users.read` for `--with-users`). An SSWS token of a read-only or super administrator works too.

## Plain-English invariants

`check` reads a controlled-English sentence, restates it formally (the *reading*), and proves it over every
user and context or returns a minimal counterexample:

```
$ okta-policy-analyzer check snapshots/acme "Only Finance can access Payroll (Workday)"
VIOLATED: Only Finance can access Payroll (Workday)
  reading: For every user who is not a member of Finance, in every context (any network, device, platform,
           risk level), accessing Payroll (Workday): the deciding rule is DENY (or no rule matches).
  note: 'only <group> can …' read as: everyone who is not in that group is denied
  Payroll policy: VIOLATED by rule 'Executives' → 2FA (any factor types)
    counterexample: member of Executives ∧ not member of Finance  (e.g. groups={Contractors, Executives}, ...)
```

Subjects (`Everyone`, `Nobody`, `<Group>`, `users who are not in <Group>`, `Only <Group> can`, `users whose
department is Finance`), contexts (`from <Zone>`, `from outside <Zone> or <Zone>`, `unless they are on <Zone>`,
`on an unmanaged device`, `on macOS`, `at high risk`), objects (`<App>`, `any app`, `apps governed by <Policy>`)
and requirements (`must be denied`, `cannot access`, `must use MFA`, `must use phishing-resistant MFA`,
`cannot … with only a password`, `must not be able to sign in without a password`, `must be handled by rule 'X'`,
`can only … from <Zone>`) combine freely; the full phrasebook is in [docs/invariants.md](docs/invariants.md).
Verdicts are **PROVED** (with the modelling assumptions the proof relies on), **VIOLATED** (who, in which
context, decided by which rule), **VACUOUS** (premise matches nobody) or **UNPARSED** (with the reason and the
closest supported phrasing or name). `--yaml-out` exports the formal assertions for `verify`.

The repository ships a Claude skill, `.claude/skills/okta-auth-invariants/SKILL.md`, that teaches an agent to
run this workflow for a security engineer: take a snapshot, orient with `analyze`, turn the question into an
invariant, confirm the reading, and explain a counterexample using the findings and fix hints.

## Making rules

`propose` takes a violated invariant and synthesises the smallest change that makes it hold: a top-priority
DENY rule whose conditions are the invariant's premise, or, for MFA/strength invariants, a stronger
verification method on each rule the counterexamples land on. It applies the change to an in-memory copy of
the snapshot, re-proves the invariant there, formally diffs before and after (who lost access, who needs
stronger authentication, and whether anything became *more* permissive) and lists findings the change
introduces. The plan is JSON containing the exact Okta API operations; `apply --dry-run` prints them,
`apply --yes` sends them and records a rollback file, `rollback --yes` undoes them. See
[docs/remediation.md](docs/remediation.md).

## Assertions

```yaml
assertions:
  - name: contractors-denied-off-network
    description: Contractors may only reach standard apps from the corporate network or VPN
    apps: [Salesforce, GitHub]                 # or `policy: <name>` or `all_apps: true`
    when:                                      # premise; clauses are AND-ed, lists are any-of
      groups_any: [Contractors]
      zones_none: [Corporate Network, VPN]
    expect:                                    # must hold for every world satisfying the premise
      access: DENY

  - name: admins-phishing-resistant
    apps: [Okta Admin Console]
    when: {groups_any: [Okta Administrators]}
    expect: {min_strength: TWO_FA_PHISHING_RESISTANT}   # DENY counts as satisfying a minimum
    with_session_policy: true                           # judge after adding the global session policy
```

Premise clauses: `groups_any`, `groups_all`, `groups_none`, `users_any`, `user_types_any`, `attributes`,
`zones_any`, `zones_none`, `registered`, `managed`, `platforms_any`, `assurance_any`, `risk`, `auth_type`, `idp`.
Expectations: `access`, `min_strength`, `max_strength`, `passwordless: false`, `password_required: true`,
`rules_any`, `rules_none`. Strength names: `DENY`, `NO_PATH`, `ONE_FA_KNOWLEDGE`, `ONE_FA_POSSESSION`,
`ONE_FA_PHISHING_RESISTANT`, `TWO_FA`, `TWO_FA_PHISHING_RESISTANT`, `TWO_FA_PHISHING_RESISTANT_HARDWARE`.

## Findings

| kind | severity | meaning |
|---|---|---|
| `deny-bypassed` | HIGH | a DENY rule is pre-empted, for part of the population it targets, by an earlier ALLOW rule that is not specific to that population (intentional carve-outs are not reported) |
| `unenrollable-requirement` | HIGH | an ALLOW rule's every accepted authenticator set contains something the matched users' enrollment policy forbids — an effective lock-out |
| `unsatisfiable-rule` | HIGH | an ALLOW rule no enabled authenticator can satisfy |
| `weak-catch-all` | HIGH | the catch-all grants single-factor access |
| `no-session-policy` | HIGH | some users are matched by no global session policy rule |
| `single-factor-rule` | MEDIUM | an explicit rule grants 1FA |
| `downgrade-path` | MEDIUM | the population a stricter rule targets can, in some context (e.g. an unmanaged device), fall through to a weaker later rule |
| `shadowed-rule` / `unsatisfiable-conditions` | MEDIUM/LOW/INFO | a rule can never apply (with the minimal set of earlier rules that cover it) |
| `policy-fall-through`, `shadowed-policy` | MEDIUM | a global session / enrollment policy applies to users it has no rule for, or never decides |
| `inactive-policy-mapped`, `missing-catch-all` | MEDIUM | structural anomalies |
| `redundant-rule`, `catch-all-weaker-than-rules`, `dangling-group`, `opaque-expression`, `unsupported-condition`, `session-without-mfa` | LOW | hygiene and transparency |
| `app-without-policy`, `ambiguous-people-condition`, `session-deny`, `no-phishing-resistant-enrollment`, ... | INFO | context |

Every finding carries *who* (a complete DNF over groups/attributes), *when* (context) where relevant, a
witness world and, for bypass and downgrade findings, a contrastive *fix hint*: the one fact of the witness
whose change would make the intended rule apply.

The report also contains a **group view**: for every group referenced by a rule, the weakest and strongest
outcome its members can obtain per policy (members may hold other memberships too), and an executive line
naming the weakest way into any app.

## Performance

Every statement in a report is a solver query, so run time scales with the number of rules and findings rather
than with the number of users. Indicative timings on a 4-core machine: the bundled fixture (5 policies, 20 rules)
in about 4 s; a synthetic tenant with 300 groups, 30 policies and 270 rules in about 95 s single-threaded
(`-j 4` divides that by the number of workers; `--no-cubes` skips the joint who+context enumeration;
`--combined-who` adds WHO descriptions for every session-rule × app-rule pair and roughly quadruples the time). Axioms are
sliced per query to the variables they touch, prime-implicant enumeration is bounded (`--dnf-limit`) with a coarse
but sound fallback, and the TLA+ export slices the state space per policy.

## Semantics and assumptions

`docs/semantics.md` lists every Okta behaviour the model encodes with its source, and every assumption made where
Okta's documentation is silent (each is also printed in the report). The authenticator characteristics table is
`src/okta_policy_analyzer/data/authenticators.yaml`; override it per org with `--authenticator-overrides`.

The encoding is an over-approximation of reality: universal claims proved by the tool ("all admins need
phishing-resistant MFA", "this rule is dead") hold in the real org; existential findings ("someone can get in
with a password only") are *possible* and always come with a witness to check.

## Layout

```
src/okta_policy_analyzer/
  okta/client.py       read-only Okta API client (pagination, rate limits)
  okta/snapshot.py     snapshot fetch + on-disk format
  okta/simulate.py     differential validation against POST /api/v1/policies/simulate
  model.py             normalised IR
  loader.py            Okta JSON -> IR
  el/                  Okta Expression Language parser + concrete evaluator
  assurance.py         constraints -> authentication paths -> strength
  smt/universe.py      symbolic variables, axioms, witnesses
  smt/el_encoder.py    EL -> z3
  smt/encoder.py       rule match, first-match chains, policy selection
  smt/dnf.py           projection + prime implicants
  analysis.py          analyses and findings
  diff.py              formal snapshot diff
  assertions.py        YAML assertions
  invariants.py        plain-English invariants -> assertions + formal reading
  remediation.py       violated invariant -> rule change proved in the model; apply / rollback
  interpreter.py       concrete reference interpreter
  tla.py               TLA+ export + TLC runner
  report.py, cli.py
tests/fixtures/acme    synthetic tenant snapshot exercising every analysis
docs/semantics.md      Okta semantics relied upon, with sources and assumptions
docs/invariants.md     controlled-English phrasebook for `check`
docs/remediation.md    how `propose` builds and verifies a fix; `apply` / `rollback`
CLAUDE.md              operating guide for Claude (setup, check, make rules)
.claude/skills/        Claude skills: okta-auth-invariants (check), okta-policy-remediation (make rules)
scripts/setup.sh       install + self-test (also the SessionStart hook in .claude/settings.json)
```
