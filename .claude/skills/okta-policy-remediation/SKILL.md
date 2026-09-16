---
name: okta-policy-remediation
description: Make or change Okta authentication policy rules safely. Use when a security engineer wants a violated invariant fixed ("make contractors unable to reach Salesforce off-VPN", "require phishing-resistant MFA for execs on Payroll", "add a rule so only Finance can open Workday"), asks Claude to create, tighten or roll back an Okta sign-on policy rule, or wants to know what a proposed rule change would do before applying it. Synthesises the rule, proves in the model that it makes the invariant hold, shows exactly who is affected, and applies it to the tenant only after explicit confirmation, with a rollback record.
---

# Okta policy remediation (propose → confirm → apply → re-verify)

Use `okta-policy-analyzer` (see `CLAUDE.md` for setup) to change authentication policies **only through this
flow**. Never hand-edit rules in the admin console or post raw API calls; the value of the tool is that every
change is proved before it is made and is undoable afterwards.

## 1. State the goal as an invariant

Turn the human's request into one sentence of the controlled English in `docs/invariants.md`
("Only Finance can access Payroll (Workday)", "Executives must use phishing-resistant MFA for Payroll
(Workday)", "Contractors can only reach Salesforce from the Corporate Network or VPN"). Run
`okta-policy-analyzer check SNAPSHOT "<sentence>"` first and show the **reading**. If it is already PROVED,
say so: there is nothing to change.

## 2. Propose

```bash
okta-policy-analyzer propose SNAPSHOT "<sentence>" --plan-out plans/<slug>.json [--rule-name "<org convention>"]
```

Read the whole output and relay it faithfully:

- **status** — `FIX_PROVED` is the only status you may apply. `FIX_INSUFFICIENT` means the synthesised change
  did not make the invariant hold (look at the "after" counterexample and say what else is in the way).
  `UNFIXABLE` explains why (rule-order invariants, premises that cannot be a rule condition such as two groups
  at once); propose the manual change instead. `ALREADY_HOLDS`, `VACUOUS`, `UNPARSED` as in `check`.
- **the operation(s)** — `CREATE rule` (a DENY/ALLOW rule inserted at the top of the policy with the premise as
  its conditions) or `UPDATE rule` (an existing rule's verification method raised to the minimum strength).
  Show the human the rule body; it is exactly what will be sent.
- **impact** — the formal before/after diff per app: `- lost access` and `^ stronger auth` are the intended
  effect; `+ NEW ACCESS` or `~ WEAKER AUTH` mean the change loosens something and must be called out
  prominently (this happens with ALLOW invariants, whose rule pre-empts everything below it).
- **new finding** — analysis findings the change introduces (e.g. the old DENY rule becomes dead, or a
  strengthened rule now requires authenticators some users cannot enroll). HIGH ones need a decision.
- **caveat** — interpretation choices and model caveats.

Prefer strength fixes (UPDATE) over new rules when both would work; they never grant access. For a DENY fix,
check whether an existing DENY rule already intends this (a `deny-bypassed` finding in `analyze`): moving that
rule above the ALLOW that pre-empts it is often the cleaner change; the tool does not reorder rules, so say so
and offer the new rule as the alternative.

## 3. Confirm

```bash
okta-policy-analyzer apply plans/<slug>.json --dry-run
```

Paste the dry-run (method, path, body) and the impact lines to the human and ask for an explicit yes for
**this plan**. Do not proceed on an earlier or general approval. Offer `--inactive` (create the rule disabled
so they can activate it in the admin console) when they are hesitant.

## 4. Apply and re-verify

```bash
set -a; source .env; set +a
okta-policy-analyzer apply plans/<slug>.json --yes [--inactive]        # writes plans/<slug>.json.applied.json
okta-policy-analyzer fetch -o snapshots/<date>-after
okta-policy-analyzer check snapshots/<date>-after "<sentence>"
okta-policy-analyzer diff snapshots/<before> snapshots/<date>-after
```

Report: the rule id(s) Okta returned, the re-check verdict on the fresh snapshot, and the diff. If the
re-check is not PROVED (Okta normalised the body differently, priorities shifted, someone else changed the
policy), say exactly that and offer the rollback below; do not try a second write without a new confirmation.

## 5. Roll back (when asked, or when re-verification fails and the human agrees)

```bash
okta-policy-analyzer rollback plans/<slug>.json.applied.json --dry-run
okta-policy-analyzer rollback plans/<slug>.json.applied.json --yes
```

Deletes rules the plan created and restores the previous bodies of rules it updated, in reverse order.

## What the tool will not do

- Reorder existing rules, edit conditions of the system catch-all rule, or touch enrollment/password/session
  policies. Describe the manual change instead.
- Apply plans that are not `FIX_PROVED` (needs `--force`, which you use only if the human asks for it by name).
- Guess names: group, app, zone and rule names must match the snapshot; `propose` prints the closest matches.

## Safety checklist before `--yes`

1. Status is `FIX_PROVED` on a snapshot taken today.
2. The human has seen the dry-run body and the impact lines and said yes to this plan.
3. No `+ NEW ACCESS` / `~ WEAKER AUTH` line, or the human has explicitly accepted it.
4. The credential in use is allowed to manage authentication policies in this org.
5. You know where the `.applied.json` record will be written.
