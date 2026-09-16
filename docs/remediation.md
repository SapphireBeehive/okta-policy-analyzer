# Making rules: propose → verify → apply → rollback

`okta-policy-analyzer propose` turns a **violated** plain-English invariant (see [invariants.md](invariants.md))
into the smallest Okta policy change that makes it hold, proves that in the model, and reports the exact
impact. `apply` sends the change to the org; `rollback` undoes it.

```
$ okta-policy-analyzer propose snapshots/acme "Only Finance can access Payroll (Workday)" --plan-out plan.json
FIX_PROVED: Only Finance can access Payroll (Workday)
  reading: For every user who is not a member of Finance, in every context …, accessing Payroll (Workday):
           the deciding rule is DENY (or no rule matches).
  Payroll policy: violated by rule 'Executives' → 2FA (any factor types)
    counterexample: member of Executives ∧ not member of Finance
  CREATE rule in policy 'Payroll policy': 'Deny: Only Finance can access Payroll (Workday)'
    why: a DENY rule at the top of the policy whose conditions are exactly the invariant's premise
    body: { "name": …, "priority": 1, "conditions": {"people": {"groups": {"include": ["00g_everyone"],
            "exclude": ["00g_finance"]}}}, "actions": {"appSignOn": {"access": "DENY"}} }
  after the change the invariant is: PROVED
  impact on Payroll (Workday): LESS_PERMISSIVE
    - lost access:   member of Executives ∧ not member of Finance
```

## How a fix is synthesised

| invariant kind | change | why it is safe |
|---|---|---|
| DENY (`must be denied`, `cannot access`, `can only … from`, `Only <Group> can`) | one new **DENY** rule at the top of each violated policy; its conditions are exactly the premise (groups include/exclude, network zone include/exclude, device managed/registered/assurance, platform, risk level, user type, an EL condition for profile attributes) | a DENY rule only removes access; the diff shows precisely who |
| strength / password (`must use MFA`, `phishing-resistant`, `hardware-protected`, `cannot … with only a password`, `must not … without a password`) | **update** the verification method of each rule a counterexample lands on to the weakest method meeting the requirement, repeating until the invariant is proved | no rule is added, no conditions change, so nobody gains access; only the affected rules' populations need stronger authentication |
| ALLOW (`must be able to access`) | one new **ALLOW** (2FA) rule at the top for the premise | flagged: it pre-empts every rule below it for those users, so the diff usually shows `NEW ACCESS` |
| rule identity (`must be handled by rule X`) | not synthesised | it is about the order or scope of existing rules; the plan explains what to change by hand |

Premises that cannot be a single Okta rule condition (membership of two groups at once, both include and
exclude zones, an authentication type or IdP) make the plan `UNFIXABLE` with the reason.

The synthesised verification methods are the Okta defaults for each strength:

| requirement | `factorMode` | constraint |
|---|---|---|
| at least 2FA | `2FA` | none (any two factor types) |
| phishing-resistant | `2FA` | `possession.phishingResistant = REQUIRED` |
| hardware-protected | `2FA` | `possession.phishingResistant = REQUIRED`, `possession.hardwareProtection = REQUIRED` |
| not a password alone | `1FA` | `possession.required = true` |
| password required / no passwordless | adds `knowledge {types: [PASSWORD], required: true}` | |

The existing `reauthenticateIn` is preserved on updates.

## What `propose` verifies before it says FIX_PROVED

1. The change is applied to an **in-memory copy** of the snapshot (new rules go to the top of their policy;
   other user rules shift down one priority; the system catch-all stays last).
2. The invariant is re-checked on the copy. `after: PROVED` is required for `FIX_PROVED`.
3. The two snapshots are **formally diffed** (`diff`) for every app of every touched policy: who lost access,
   who now needs stronger authentication, and, if anything became more permissive, who gained access or got
   weaker requirements. A more-permissive result is always a caveat.
4. The full analysis runs on both; HIGH/MEDIUM findings that exist only after the change are listed (a
   pre-empted DENY rule that is now dead, a requirement some matched users cannot enroll, a weak new rule).

`--patched-snapshot DIR` writes the copy so you can run `analyze`, `who` or `export-tla` on it.

## Plan file

`--plan-out` writes JSON with the sentence, reading, status, before/after verdicts, the assertion, the
operations (`op: create|update`, `policy_id`, `rule` body, and for updates `rule_id` and `previous` body), the
diff and new findings. It is the only input `apply` takes, so a reviewer sees exactly what will be sent.

## `apply`

```bash
okta-policy-analyzer apply plan.json --dry-run                # prints POST/PUT requests, sends nothing
okta-policy-analyzer apply plan.json --yes [--inactive]       # sends; needs $OKTA_ORG_URL + a token that can manage policies
```

- Refuses plans whose status is not `FIX_PROVED` (override only with `--force`).
- Refuses to send without `--yes`.
- `--inactive` creates/updates rules with status INACTIVE (and deactivates a created rule) for staged rollout.
- Sends only the fields Okta accepts (`name`, `priority`, `status`, `type`, `conditions`, `actions`).
- Writes `plan.json.applied.json`: the rule ids Okta returned and, for updates, the previous bodies.
- Stops at the first API error; the record contains what was already done so `rollback` can undo it.

After applying, always take a fresh snapshot and re-run `check` (and `diff` against the pre-change snapshot).
The model's prediction and the org should agree; if they do not, roll back and investigate.

## `rollback`

```bash
okta-policy-analyzer rollback plan.json.applied.json --dry-run
okta-policy-analyzer rollback plan.json.applied.json --yes
```

Deletes created rules and PUTs the previous bodies of updated rules, in reverse order of application.

## Limits

- No reordering of existing rules and no edits to the catch-all rule's conditions (Okta does not allow the
  latter; the tool can still raise the catch-all's verification method).
- The synthesised rule matches the premise of the invariant as stated; if the human meant a broader or
  narrower population, restate the invariant rather than editing the body.
- Session (global session policy), enrollment, password and account-management policies are out of scope for
  `propose`.
