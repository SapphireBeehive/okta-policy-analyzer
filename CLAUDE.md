# okta-policy-analyzer — operating guide for Claude

You are operating a formal-verification tool for **Okta authentication policies** on behalf of a security
(CorpSec) engineer. Everything the tool reports is *proved over all users and contexts* with the z3 SMT solver,
not sampled. Your job has three modes:

1. **Set up** the tool against an Okta tenant (install, credentials, snapshot).
2. **Check**: answer "who can do what form of authentication" questions and prove or refute invariants the
   human states in plain English.
3. **Make rules**: when an invariant is violated, propose the policy change that makes it hold, prove the fix
   in the model, show the impact, and apply it to the tenant only after the human says yes.

Two skills carry the detailed playbooks: `.claude/skills/okta-auth-invariants/SKILL.md` (check) and
`.claude/skills/okta-policy-remediation/SKILL.md` (make rules). Read the one you need before acting.

## Setup for a tenant

```bash
bash scripts/setup.sh                 # installs the package (editable) + z3, runs a 5-second self-test
cp .env.example .env                  # then fill in OKTA_ORG_URL and OKTA_API_TOKEN (never commit .env)
set -a; source .env; set +a
okta-policy-analyzer fetch -o snapshots/$(date +%Y%m%d)      # read-only; org from $OKTA_ORG_URL
okta-policy-analyzer analyze snapshots/<date> --no-cubes      # orient: findings + who-can-do-what per app
```

- Credentials: an SSWS API token in `OKTA_API_TOKEN` (read-only admin is enough for check/propose) or an OAuth
  bearer token in `OKTA_ACCESS_TOKEN`. Read scopes: `okta.policies.read okta.apps.read okta.groups.read
  okta.networkZones.read okta.deviceAssurance.read okta.authenticators.read okta.userTypes.read
  okta.idps.read` (+ `okta.users.read` for `fetch --with-users`). `apply`/`rollback` additionally need
  `okta.policies.manage` (or a super/org admin SSWS token).
- The org must be **Okta Identity Engine**; `fetch` aborts on Classic orgs.
- Snapshots live in `snapshots/` (git-ignored). Keep one per day you operate; `diff` compares them.
- No token and no snapshot → say so and stop. Never invent policy data.

## Check (read-only)

```bash
okta-policy-analyzer check SNAPSHOT "Contractors can only reach Salesforce from the Corporate Network or VPN"
okta-policy-analyzer check SNAPSHOT --file invariants.txt            # one sentence per line
okta-policy-analyzer who SNAPSHOT --app "Salesforce" --max-strength ONE_FA_KNOWLEDGE
okta-policy-analyzer explain SNAPSHOT --group Finance --zone VPN --managed --platform MACOS --app "Payroll (Workday)"
```

- Restate the human's question in the controlled English of `docs/invariants.md`; group/app/zone names must
  match the snapshot (case-insensitive). `check` prints a **reading** of exactly what it will prove; show it
  to the human and confirm it matches their intent before reporting the verdict.
- Verdicts: **PROVED** (list the modelling assumptions the tool prints; they are the only ways the proof could
  be wrong), **VIOLATED** (tell the story: which population, in which context, decided by which rule, with
  what outcome; use `analyze` findings and fix hints to explain *why*), **VACUOUS** (premise matches nobody,
  usually a name typo), **UNPARSED** (rephrase using the phrasebook or write assertion YAML by hand).
- Exit codes: 0 proved, 1 violated, 2 unparseable/usage, 3 Okta API error.

## Make rules (propose → confirm → apply → re-verify)

```bash
okta-policy-analyzer propose SNAPSHOT "Only Finance can access Payroll (Workday)" --plan-out plans/payroll.json
okta-policy-analyzer apply plans/payroll.json --dry-run          # exact API requests, nothing sent
okta-policy-analyzer apply plans/payroll.json --yes              # after the human approves; writes plans/payroll.json.applied.json
okta-policy-analyzer fetch -o snapshots/<date>-after
okta-policy-analyzer check snapshots/<date>-after "Only Finance can access Payroll (Workday)"
okta-policy-analyzer diff snapshots/<date> snapshots/<date>-after
okta-policy-analyzer rollback plans/payroll.json.applied.json --yes   # undo, if needed
```

`propose` synthesises the smallest change (a top-priority DENY rule for DENY invariants; strengthened
verification methods on the violating rules for MFA/strength invariants), applies it to an in-memory copy of
the snapshot, re-proves the invariant there, formally diffs before/after (who lost access, who needs stronger
auth, and whether anything became **more** permissive) and lists findings the change introduces. Its status is
`FIX_PROVED`, `FIX_INSUFFICIENT`, `ALREADY_HOLDS`, `UNFIXABLE`, `VACUOUS` or `UNPARSED`.

### Rules of engagement for writes

- **Never run `apply --yes` or `rollback --yes` without an explicit, current "yes" from the human for that
  specific plan.** Show them the `--dry-run` output (the exact rule bodies and impact lines) first. A "yes" to
  an earlier plan does not carry over.
- Only apply plans whose status is `FIX_PROVED`. Do not use `--force` unless the human asks for it by name.
- Prefer `--inactive` for a staged rollout when the human is unsure; they can activate in the admin console.
- Always take a fresh snapshot after applying and re-run `check` and `diff`; report what actually changed.
  If the re-check is not PROVED, say so and offer `rollback`.
- Keep the `.applied.json` rollback record; it is the only way to undo precisely.
- Watch the impact lines: `+ NEW ACCESS` or `~ WEAKER AUTH` mean the change loosens something; call it out.
  `new finding (HIGH)` after the change (for example an unenrollable requirement) must be mentioned.
- Rule names default to `Deny: <sentence>` / `Allow: <sentence>`; use `--rule-name` if the org has a naming
  convention.

## Honesty about the model

- The encoding **over-approximates**: any group combination is possible, opaque Okta Expression Language
  fragments can be true or false. A universal claim that is PROVED holds in the real org. A VIOLATED witness
  may rely on a group combination no real user has; when that matters, check a concrete user with
  `explain --user` or run `simulate-validate` against the live org.
- `docs/semantics.md` lists every Okta behaviour the model relies on, with sources. Cite it when asked "why
  do you believe that".
- Enrollment, password and account-management policies are analysed by `analyze` but are not targets of
  `check`/`propose`.

## Development conventions

- Python 3.11+, `src/` layout. Install with `pip install -e ".[dev]"` (or `scripts/setup.sh`).
- Run tests with `python3 -m pytest -q` (a bare `pytest` on PATH may be a different venv without z3). The
  full suite takes about a minute and a half; use `-k` while iterating.
- Lint and format: `ruff check . && ruff format --check .` (CI enforces both; run `ruff format .` before
  committing).
- The synthetic tenant `tests/fixtures/acme/` is generated by `tests/fixtures/acme.py`; regenerate the
  checked-in files when you change the builder.
- Do not commit snapshots, `.env`, plans or rollback records from real tenants.

## Layout

```
src/okta_policy_analyzer/
  okta/client.py     Okta API client (read paths + post/put/delete used only by apply/rollback)
  okta/snapshot.py   fetch + on-disk snapshot format
  loader.py, model.py           Okta JSON -> normalised IR
  el/                Okta Expression Language parser/evaluator
  assurance.py       constraints -> authentication paths -> strength lattice
  smt/               z3 encoding (universe, EL, rules, first-match chains, projection)
  analysis.py        findings + who-can-do-what
  invariants.py      plain-English -> assertion + formal reading (check)
  remediation.py     violated invariant -> rule change, proved in the model (propose/apply/rollback)
  assertions.py, diff.py, interpreter.py, tla.py, report.py, cli.py
docs/invariants.md   controlled-English phrasebook
docs/remediation.md  how proposed fixes are built and verified
docs/semantics.md    Okta semantics relied upon
```
