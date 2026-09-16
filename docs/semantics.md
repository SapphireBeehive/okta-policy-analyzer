# Okta semantics the model relies on

This document lists every behaviour of Okta Identity Engine that the analyzer encodes, where it comes from,
and the assumptions the tool makes where Okta's documentation is silent. The same assumptions are printed in
every report under *Modelling assumptions*. When in doubt, validate against a live org with
`okta-policy-analyzer simulate-validate`, which compares the encoder with Okta's own policy simulation API.

Sources: the official Okta Management OpenAPI specification (`okta-management-openapi-spec`, Policy /
Group / NetworkZone / DeviceAssurance / Authenticator tags), developer.okta.com concept pages (Policies,
Expression Language, Identity Engine EL), help.okta.com (Global session policies, Authentication policies,
Authenticators, Device assurance, Group rules) and Okta support knowledge-base articles.

## 1. Which policy applies

| Fact | Source | Encoding |
|---|---|---|
| Each app maps to exactly one authentication policy (`ACCESS_POLICY`) through `_links.accessPolicy` / `/policies/{id}/mappings`; several apps may share a policy. Authentication policies have no policy-level conditions. | OpenAPI Policy tag; help "Authentication policies" | `Tenant.apps[*].access_policy_id` |
| Within a policy, rules are evaluated in ascending `priority`; the first rule whose conditions all hold decides. The Okta-created catch-all (`system: true`, priority 99, no conditions) is always last and cannot be deleted. | OpenAPI Policy tag ("each of the rules ... is considered in turn, in the order specified by the rule priority") | `eff_i = match_i ∧ ¬∨_{j<i} match_j` |
| `INACTIVE` rules are skipped. | Lifecycle semantics; catch-all has no deactivate link | `Policy.active_rules()` |
| Global session (`OKTA_SIGN_ON`), enrollment (`MFA_ENROLL`) and password policies are chosen by policy priority: the first *active* policy whose `people.groups.include` intersects the user's groups **and that has a matching rule** decides. A group-matching policy with no matching rule falls through to the next policy. | OpenAPI Policy tag: "If none of the policy rules have conditions that can be met, then the next policy in the list is considered." | `selected_p = applies_p ∧ ∨match ∧ ¬∨_{q<p} selected_q` |
| The default policy of each type (`system: true`) is assigned to *Everyone* and is last. A non-default policy without a group assignment applies to nobody. | developer.okta.com Policies concept; help "Create a global session policy" | `policy_applies()` |
| The Okta account management policy (`_embedded.resourceType = END_USER_ACCOUNT_MANAGEMENT`) is an `ACCESS_POLICY` that governs self-service flows, not app access. | OpenAPI `listPolicies` notes | Kept apart in `Tenant.account_management_policies` |

## 2. Rule conditions

All conditions of a rule are AND-ed; an absent condition means *any*.

| Condition | Semantics encoded | Source / assumption |
|---|---|---|
| `people.users` / `people.groups` | `(includes empty ∨ user ∈ users.include ∨ ∃g ∈ groups.include: member) ∧ user ∉ users.exclude ∧ ∀g ∈ groups.exclude: ¬member`. Exclusion always wins. The two include lists are OR-ed. | UI wording "At least one of ... AND none of ..."; **assumption A1** (OR of includes) — flagged as `ambiguous-people-condition` when both lists are non-empty |
| `network` | `ANYWHERE` = any; `ZONE` with `include` = inside at least one zone; with `exclude` = inside none of them; both = conjunction. Zones are independent predicates: a request may be in several zones or in none. | OpenAPI `PolicyNetworkCondition`; help "Network zones" |
| `device` | `registered: true` = device registered with Okta Verify; `managed: true` = managed (implies registered); `assurance.include` = device satisfies **at least one** listed device assurance policy; each assurance policy implies its platform and (assumption) a registered device. | OpenAPI `DeviceAccessPolicyRuleCondition`; help "Device assurance" ("multiple ... are OR conditions") |
| `platform` | `MOBILE` = iOS/Android, `DESKTOP` = macOS/Windows/ChromeOS/Linux, `os.type` pins the platform, `os.expression` is opaque. | OpenAPI `PlatformPolicyRuleCondition` |
| `riskScore.level` | Exactly that level (LOW/MEDIUM/HIGH); `ANY` = any. | help "Risk scoring" ("limits the rule to only the specified risk level") |
| `userType` | `(include empty ∨ type ∈ include) ∧ type ∉ exclude`. | OpenAPI `UserTypeCondition` |
| `elCondition` | Interpreted exactly where possible (attribute equality, string predicates on attributes, group functions, `security.risk.level`, `device.profile.*`); every other fragment is a **free Boolean** named after its source text (a sound over-approximation, shared between rules with the identical text). A malformed expression never matches in Okta; the free Boolean covers both outcomes. | developer.okta.com "Okta Expression Language in Identity Engine"; Terraform provider docs |
| `authContext.authType`, `identityProvider`, `risk.behaviors` (global session rules) | Enum variables; behaviours are opaque atoms (any-of). | OpenAPI `OktaSignOnPolicyRuleConditions`; response examples |

## 3. Rule actions and authentication strength

| Fact | Source | Encoding |
|---|---|---|
| `appSignOn.access` is `ALLOW` or `DENY`; an ALLOW carries a `verificationMethod`. | OpenAPI `AccessPolicyRuleApplicationSignOn` | `AccessAction` |
| `ASSURANCE`: `factorMode` 1FA needs one factor, 2FA needs two **distinct factor types** (knowledge / possession / inherence). `constraints` is a list of constraint sets: one set must be satisfied (OR), and every constraint inside a set must be (AND). | OpenAPI `AccessPolicyConstraint` description | `assurance.paths_for()` |
| A possession authenticator that performs user verification (FastPass or Okta Verify push with biometrics, FIDO2 with UV, smart card with PIN) supplies the second factor type and satisfies 2FA alone; Okta Verify TOTP does not; password + security question is one type. | help "Multifactor authentication" / passwordless docs | single-method 2FA paths with `uses_user_verification` |
| A constraint with `required: false` (only `excludedAuthenticationMethods`) removes methods but does not demand its factor type. | OpenAPI `AccessPolicyConstraint.required` | `Constraint.required` |
| Possession qualifiers `phishingResistant`, `hardwareProtection`, `deviceBound`, `userPresence` (default REQUIRED), `userVerification` are matched against the authenticator characteristics table (`data/authenticators.yaml`, adapted from help "Authenticator characteristics"). Phishing-resistant: FIDO2/passkeys, Okta FastPass, smart card. | help "Phishing-resistant authentication"; support KB on FastPass | `satisfying_methods()` |
| "Conditional" characteristics (FastPass hardware protection depends on the device's secure hardware; synced passkeys are not hardware-bound) satisfy a REQUIRED constraint because Okta enforces the property at verification time, but are not counted as guaranteed when classifying a rule that does not require them. | help; Okta security blog | `AuthPath.hardware_enforced` |
| `AUTH_METHOD_CHAIN`: chains are OR-ed; steps within a chain are ordered and AND-ed; methods within a step are OR-ed. | OpenAPI `AuthenticationMethodChain` | `_chain_paths()` |
| Strength order used in reports: DENY < unsatisfiable ALLOW < 1FA knowledge < 1FA possession < 1FA phishing-resistant < 2FA < 2FA phishing-resistant < 2FA phishing-resistant + hardware. A rule's class is its **weakest** accepted path. | tool definition | `Strength` |

## 4. Global session policy and composition

| Fact | Source | Encoding |
|---|---|---|
| The global session policy runs when no Okta session exists; the authentication policy runs on every app access. Factors verified for the session are credited towards the app policy. | support KB "End User Experience when MFA is Required in Policies"; help "Modify app sign-in policies for first-party apps" | `combined_strength()` = union of both requirements |
| `primaryFactor: PASSWORD_IDP` forces a password (or IdP assertion) even for a passwordless app rule; `PASSWORD_IDP_ANY_FACTOR` delegates to the app policy. `requireFactor: true` forces a second factor type even for a 1FA app rule. A session `DENY` denies every app. | help "Global session policies" | `combined_strength()` |
| The session policy never constrains *which* possession factor is used, so phishing resistance comes from the app rule alone. | — (**assumption**) | `combined_strength()` |

## 5. Enrollment feasibility

| Fact | Source | Encoding |
|---|---|---|
| A user can hold an authenticator only if their deciding enrollment policy lists it with `enroll.self` REQUIRED or OPTIONAL; authenticators absent from `settings.authenticators` are not enrollable. Classic `settings.factors` keys are mapped onto authenticator keys. | OpenAPI `AuthenticatorEnrollmentPolicySettings` ("Policy settings are included only for those authenticators that are enabled") | `_enrollable()` |
| An ALLOW rule whose every accepted path needs an authenticator the user cannot enroll is an effective lock-out. | consequence | finding `unenrollable-requirement` |
| Enrollment-rule actions `NEVER*` (blocking just-in-time enrollment) are **not** modelled; recovery-driven enrollments outside the enrollment policy are not modelled. | **assumption** | — |

## 6. Groups and users

| Fact | Source | Encoding |
|---|---|---|
| Groups are flat; *Everyone* (`BUILT_IN`) contains every user. | help "Groups" | `member[Everyone] = true` |
| Active group rules add members: `expression ∧ user ∉ exclude ⇒ member(target)`. Manual membership and members left behind by deactivated rules mean only the forward implication is sound. `--strict-group-rules` opts into the equivalence. | help "Group rules", support KB on deactivation | axioms |
| Users named in include/exclude lists are modelled individually; when the snapshot contains users (`--with-users`), their memberships and user type are pinned. | — | `user_is[u]` |
| Groups referenced by a rule but absent from the snapshot are treated as empty (deleted). | **assumption** (closed world) | axiom `¬member[g]` |

## 7. Pre-policy filtering

| Fact | Source | Encoding |
|---|---|---|
| Requests from an active IP blocklist zone are rejected before any policy evaluation. | help "IP blocklist" ("blocks these requests before any type of policy evaluation occurs") | axiom `¬zone[blocklist]` (disable with `--evaluate-blocklisted`) |
| Inactive zones and deleted zones/assurance policies match nothing. | **assumption** | axioms |

## 8. Soundness statement

Let R be the set of real (user, context) states and S the set of solver models. The encoding keeps R ⊆ S:
interpreted atoms have Okta's semantics on their finite domains, uninterpreted atoms are free, and every axiom is a
genuine invariant of Okta's eventual state. Therefore a **universal** claim proved by the tool ("every user reaching
app A needs phishing-resistant MFA", "rule X can never apply") holds in reality, while an **existential** finding
("someone can get in with a password only") is *possible* and is always reported with a witness so an analyst can
check whether the free atoms are realisable. Exceptions to R ⊆ S are the closed-world treatment of deleted groups
and name-based group functions, and time-dependent expressions frozen as free Booleans; both are listed in the
report's assumptions.
