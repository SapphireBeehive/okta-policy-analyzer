# Plain-English invariants

`okta-policy-analyzer check` lets a security engineer state a property of the org's authentication policies in
controlled English and get back either a **proof** that it holds for every user in every context, or a
**counterexample** naming the population, the context and the rule that breaks it.

```
$ okta-policy-analyzer check snapshots/acme "Contractors can only reach Salesforce from the Corporate Network or VPN"

VIOLATED: Contractors can only reach Salesforce from the Corporate Network or VPN
  reading: For every user who is a member of Contractors, from outside Corporate Network and VPN, accessing
           Salesforce: the deciding rule is DENY (or no rule matches).
  note: 'can only … from <zones>' read as: outside those zones the outcome must be DENY
  Standard apps policy: VIOLATED by rule 'Managed device passwordless' → 2FA phishing-resistant
    counterexample: device passes macOS secure ∧ device managed ∧ member of Contractors ∧ not member of
                    Service Accounts ∧ not in zone Corporate Network ∧ not in zone VPN
    who (in some context): member of Contractors ∧ not member of Service Accounts
```

Every sentence is turned into an [assertion](../README.md#assertions) (the same YAML `verify` checks; export it
with `--yaml-out`) and into a **reading**: an unambiguous restatement of exactly what is proved. Always read the
reading. The parser never guesses: if it cannot read a sentence with confidence it says why and suggests the
closest supported phrasing or the closest matching group/app/rule name.

## Verdicts

| verdict      | meaning                                                                                           | exit code |
|--------------|---------------------------------------------------------------------------------------------------|-----------|
| **PROVED**   | holds for every user (every group combination, attribute value, user type) in every context (every network zone combination, device state, platform, risk level). The modelling assumptions the proof relies on are listed; they are the only ways it could be wrong. | 0 |
| **VIOLATED** | a minimal counterexample exists: the *who* (population), the context and the rule that decides it, plus a fully concrete example world you can replay with `explain`. | 1 |
| **VACUOUS**  | the premise matches no user/context (a contradictory context, or a misspelled name that happens to match nothing). Nothing was proved. | 0 |
| **UNPARSED** | the sentence could not be read; the reason and suggestions are printed.                          | 2 |

A `DENY` outcome satisfies every strength requirement ("must use MFA" is about *how* someone gets in, not
*whether*). Say `must be able to access` when you want to prove access is granted.

## Grammar

A sentence is **subject** + **context** + **requirement** + **object**, in any order that reads naturally.
Names of groups, apps, network zones, device assurance policies, user types, rules and user logins are matched
against the snapshot **exactly, case-insensitively, longest match first**. Multi-word names work
(`Payroll (Workday)`, `Corporate Network`).

### Subject — who

| phrase | premise |
|---|---|
| `Everyone`, `Anyone`, `All users`, `Users …`, or no subject | every user |
| `Nobody`, `No one`, `No user` | every user, and the requirement is negated (see below) |
| `<Group>`, `members of <Group>`, `<Group> users` | member of the group |
| `<Group> or <Group>` | member of either |
| `<Group> who are also <Group>`, `both <Group> and <Group>` | member of all |
| `users who are not in <Group>`, `users outside <Group>`, `non-<Group>` | not a member |
| `Only <Group> can …` | everyone **not** in the group is denied |
| `users whose <attribute> is '<value>'`, `users with <attribute> set to <value>` | `user.<attribute> == value` (Okta profile attribute) |
| `<user type> user type`, `users of user type <name>` | user type |
| `<login>` (e.g. `breakglass@acme.com`) | that user (only users named by some rule can be referenced) |

### Context — where and how

| phrase | premise |
|---|---|
| `from <Zone>`, `on the <Zone>`, `inside <Zone>` | request from inside the zone |
| `from outside <Zone>`, `not on <Zone>`, `off <Zone>` | request from outside |
| `from outside <Zone> or <Zone>` | outside all of them |
| `from the internet`, `from an unknown network`, `off-network` | inside none of the org's zones |
| `… unless they are on <Zone>` | see *unless* below |
| `on a managed device` / `on an unmanaged device` | device managed / not managed |
| `on a registered device` / `on an unregistered device` | Okta Verify registered / not |
| `on macOS`, `on Windows`, `on iOS`, `on Android`, `on ChromeOS`, `on Linux` | platform |
| `on a device that passes <Device assurance policy>` | device assurance satisfied |
| `at high risk`, `high-risk sign-ins`, `when risk is medium` | Okta risk level |

No context means **every** context.

### Object — which app

| phrase | scope |
|---|---|
| `access/reach/sign in to/log in to/open/use <App label>` | that app's authentication policy |
| `<App> or <App>`, `<App> and <App>` | each app |
| `any app`, `all apps`, `every application`, `anywhere` | every authentication policy |
| `apps governed by <Policy name>` | that policy |

### Requirement — what must be true of the deciding rule

| phrase | expectation |
|---|---|
| `must be denied`, `cannot access`, `must not be able to sign in`, `may not …`, `are blocked` | deciding rule is DENY (or nothing matches) |
| `must be able to access`, `must always have access`, `should be able to` | deciding rule is ALLOW |
| `must use MFA`, `need two factors`, `require multi-factor`, `strong authentication` | at least 2FA |
| `must use phishing-resistant MFA` | at least 2FA phishing-resistant |
| `must use hardware-protected MFA`, `hardware-backed` | at least 2FA phishing-resistant + hardware-protected |
| `cannot … with only a password`, `password alone`, `single-factor` | at least 1FA possession (a password alone never suffices) |
| `cannot … without phishing-resistant MFA`, `cannot … with less than MFA` | that minimum strength |
| `must not be able to sign in without a password`, `no passwordless access` | every accepted path includes the password |
| `must always enter a password`, `password required`, `password plus a second factor` | every accepted path includes the password |
| `must be handled by rule 'X'`, `must hit rule X` | the deciding rule is X |
| `rule 'X' must never apply`, `must never be decided by rule X` | the deciding rule is not X |
| `can only … from <Zone> or <Zone>` | outside those zones the outcome is DENY |
| `… even after the global session policy`, `… including the session policy` | judge the requirement after adding the global session policy's requirements to the app policy's |

### `unless`

`unless they are on <Zone>` splits the world: the stated requirement applies **outside** the zone.

- `Finance must use MFA for Payroll unless they are on the Corporate Network` → outside the Corporate Network,
  Finance's deciding rule requires at least 2FA.
- `Contractors cannot access GitHub unless they are on the VPN` → outside the VPN, contractors are denied.
- `Sales can access Salesforce unless they are on the VPN` (a positive capability with an exception) → inside
  the VPN, Sales are denied.

The note printed with the reading says which way it was read.

## Reading the output

- **reading** — what was proved, formally: `For every user who <premise>, <context>, accessing <scope>:
  <requirement>.`
- **note** — an interpretation the parser chose (e.g. `'with only a password' read literally`). If a note
  does not match your intent, rephrase.
- **counterexample** — a minimal conjunction of facts (a prime implicant) that forces the violation, followed
  by one fully concrete example world. Replay it:
  `okta-policy-analyzer explain SNAPSHOT --group Contractors --managed --platform MACOS --assurance "macOS secure" --app GitHub`.
- **who (in some context)** — the population alone, with the context projected away.
- **proof relies on these modelling assumptions** — listed only for PROVED results; see
  [semantics.md](semantics.md) for the source of each.

## Batch use

```bash
okta-policy-analyzer check snapshots/acme --file corpsec-invariants.txt          # one sentence per line, # comments
okta-policy-analyzer check snapshots/acme --file corpsec-invariants.txt --format json -o results.json
okta-policy-analyzer check snapshots/acme --file corpsec-invariants.txt --yaml-out policy-assertions.yaml
okta-policy-analyzer verify snapshots/acme --assertions policy-assertions.yaml   # the exported YAML, in CI
```

Exit code 0 when everything is proved (or vacuous), 1 when any invariant is violated, 2 when a sentence could
not be read or a name could not be resolved.

## Limits

- The grammar is controlled English, not free text. One requirement per sentence; split compound policies into
  several sentences.
- Names must match the snapshot. `check` prints the closest matches when a name is off by a word.
- Enrollment policies, password policies and the account-management policy are not addressed by `check`
  (use `analyze`; its `unenrollable-requirement` finding covers the enrollment interaction).
- A PROVED verdict is a proof about the **model**. The model over-approximates the org (any group
  combination is possible, opaque expression fragments can be either true or false), so a universal claim
  proved here holds in the real org. A VIOLATED verdict's witness may rely on a group combination no real
  user has; `explain --user` and `simulate-validate` check a concrete case against the live org.
