"""Plain-English invariants → formal assertions → proof or counterexample.

A security engineer writes a sentence such as

    Contractors can only reach Salesforce from the Corporate Network or VPN.
    Okta Administrators must use phishing-resistant MFA for the Okta Admin Console.
    Nobody can access any app with only a password.
    Users outside the VPN on an unmanaged device must be denied access to Payroll (Workday).

:func:`parse_invariant` reads it with a small controlled grammar (keyword and name matching against the
snapshot's groups, apps, zones, device assurance policies and user types) and produces an
:class:`~okta_policy_analyzer.assertions.Assertion` together with a *reading*: an unambiguous restatement of
exactly what will be proved ("for every user in Contractors and every context outside Corporate Network and
outside VPN, the deciding rule of Salesforce's policy is DENY"). :func:`check_invariants` then hands the
assertions to the solver-backed checker and reports PROVED (with the modelling assumptions the proof relies
on), VIOLATED (with a minimal counterexample world and the rule that decides it) or VACUOUS (the premise
matches nobody).

The grammar is deliberately conservative: when a sentence cannot be read with confidence the parser says why
and suggests the closest supported phrasing instead of guessing.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from .analysis import Analyzer
from .assertions import Assertion, AssertionChecker, AssertionResult
from .assurance import Strength
from .model import DevicePlatform, Tenant

# ------------------------------------------------------------------------------------------ vocabulary

_STRENGTH_PHRASES: list[tuple[str, Strength]] = [
    (r"hardware[- ]?(?:protected|backed|bound)", Strength.TWO_FA_PHISHING_RESISTANT_HARDWARE),
    (r"phishing[- ]?resistant", Strength.TWO_FA_PHISHING_RESISTANT),
    (
        r"\bmfa\b|multi[- ]?factor|two[- ]?factor|\b2fa\b|second factor|two factors|strong authentication",
        Strength.TWO_FA,
    ),
]
_PASSWORD_ONLY = re.compile(
    r"(?:with )?(?:only|just) (?:a |their )?password|(?:a |their )?password alone|password[- ]only|single[- ]factor|with (?:a |one |a single )?(?:single )?factor(?: only)?",
    re.I,
)
_PASSWORDLESS = re.compile(r"passwordless|without (?:a |their |entering a )?password", re.I)
_DENY_PHRASES = re.compile(
    r"must be denied|(?:must|should|shall) not (?:be able to |be allowed to )?(?:access|reach|sign in|log in|log on|open|use|get in)|"
    r"cannot|can't|can not|may not|are denied|is denied|be blocked|must be blocked|never be able to|no access",
    re.I,
)
_ALLOW_PHRASES = re.compile(
    r"must be (?:allowed|able to)|must (?:always )?have access|should be able to|are allowed to", re.I
)
_NOBODY = re.compile(r"^(?:nobody|no one|no-one|no user|no users|no member|no members)\b", re.I)
_ONLY_SUBJECT = re.compile(
    r"^only (?:members of |users in |the )?(.+?)(?: group| members| users)? (?:can|may|are allowed to|should be able to|must be able to) ",
    re.I,
)
_CAN_ONLY_FROM = re.compile(
    r"(?:can|may) only (?:access|reach|sign in to|log in to|use|open) (.+?) (?:from|on|while on|when on|via) (.+)$",
    re.I,
)
_UNLESS = re.compile(
    r"\bunless (?:they are |they're |the user is |on |from |connected to |using )?(.+)$", re.I
)
_SESSION = re.compile(
    r"(?:even |also )?(?:after|considering|including|taking into account|with) the (?:global )?session policy",
    re.I,
)
_RULE_ANY = re.compile(
    r"(?:must|should) (?:be (?:handled|decided|matched) by|match|hit) (?:the )?rule (?:['\"]([^'\"]+)['\"]|(.+?))(?: for)?\s*$",
    re.I,
)
_RULE_NONE = re.compile(
    r"rule (?:['\"]([^'\"]+)['\"]|(.+?)) (?:must|should) never (?:apply|match|fire|decide)|"
    r"(?:must|should) never (?:be (?:handled|decided|matched) by|match|hit) (?:the )?rule (?:['\"]([^'\"]+)['\"]|(.+?))(?: for)?\s*$",
    re.I,
)
_RISK = re.compile(
    r"\b(high|medium|low)[- ]risk\b|\brisk (?:is|of) (high|medium|low)\b|\bat (high|medium|low) risk\b", re.I
)
_UNMANAGED = re.compile(r"unmanaged|not managed|non-managed|personal device|byod", re.I)
_MANAGED = re.compile(r"\bmanaged\b", re.I)
_UNREGISTERED = re.compile(r"unregistered|not registered", re.I)
_REGISTERED = re.compile(r"\bregistered\b", re.I)
_PLATFORMS = {
    "macos": DevicePlatform.MACOS,
    "mac os": DevicePlatform.MACOS,
    "mac": DevicePlatform.MACOS,
    "osx": DevicePlatform.MACOS,
    "windows": DevicePlatform.WINDOWS,
    "ios": DevicePlatform.IOS,
    "iphone": DevicePlatform.IOS,
    "ipad": DevicePlatform.IOS,
    "android": DevicePlatform.ANDROID,
    "chromeos": DevicePlatform.CHROMEOS,
    "chromebook": DevicePlatform.CHROMEOS,
    "linux": DevicePlatform.LINUX,
}
_ALL_APPS = re.compile(
    r"\b(?:any|all|every|each) (?:app|apps|application|applications)\b|\banywhere\b|\banything\b|\ball resources\b",
    re.I,
)
_EVERYONE = re.compile(
    r"^(?:everyone|anyone|all users|every user|any user|users|all members|everybody)\b", re.I
)
_CONTEXT_SUBJECT = re.compile(
    r"sign[- ]?ins?|log[- ]?ins?|logons?|sessions?|requests?|attempts?|access|authentications?|connections?|"
    r"devices?|traffic|users?|people|members|employees|staff|accounts?|anyone|anybody|someone|somebody",
    re.I,
)
_INTERNET = re.compile(
    r"from the internet|from outside any zone|from an unknown network|from (?:an )?untrusted network|off[- ]network|outside (?:all|every|any) (?:defined )?zones?",
    re.I,
)


@dataclass
class ParsedInvariant:
    sentence: str
    assertion: Assertion | None
    reading: str  # formal restatement of what is checked
    problems: list[str] = field(default_factory=list)  # why it could not be parsed
    notes: list[str] = field(default_factory=list)  # interpretation choices the user should confirm

    @property
    def ok(self) -> bool:
        return self.assertion is not None and not self.problems


@dataclass
class InvariantResult:
    parsed: ParsedInvariant
    results: list[AssertionResult]
    assumptions: list[str]

    @property
    def verdict(self) -> str:
        if not self.parsed.ok:
            return "UNPARSED"
        if any(r.error for r in self.results):
            return "ERROR"
        if all(r.vacuous for r in self.results):
            return "VACUOUS"
        return "PROVED" if all(r.holds for r in self.results) else "VIOLATED"

    def to_dict(self) -> dict[str, Any]:
        return {
            "sentence": self.parsed.sentence,
            "verdict": self.verdict,
            "reading": self.parsed.reading,
            "notes": self.parsed.notes,
            "problems": self.parsed.problems,
            "assertion": _assertion_dict(self.parsed.assertion) if self.parsed.assertion else None,
            "results": [r.to_dict() for r in self.results],
            "assumptions": self.assumptions if self.verdict == "PROVED" else [],
        }


def _assertion_dict(a: Assertion) -> dict[str, Any]:
    d: dict[str, Any] = {"name": a.name}
    if a.description:
        d["description"] = a.description
    if a.all_apps:
        d["all_apps"] = True
    if a.apps:
        d["apps"] = a.apps
    if a.policy:
        d["policy"] = a.policy
    d["when"] = a.when
    d["expect"] = a.expect
    if a.with_session_policy:
        d["with_session_policy"] = True
    return d


# ------------------------------------------------------------------------------------------ name matching


class _Names:
    """Longest-match lookup of tenant names (groups, apps, zones, assurance policies, user types) in a sentence."""

    def __init__(self, tenant: Tenant):
        self.groups = {g.name: g.id for g in tenant.groups.values() if not g.is_everyone}
        self.apps = {a.label: a.id for a in tenant.apps.values() if a.access_policy_id}
        self.policies = {p.name: p.id for p in tenant.access_policies}
        self.zones = {z.name: z.id for z in tenant.zones.values() if z.usage == "POLICY"}
        self.assurances = {d.name: d.id for d in tenant.device_assurances.values()}
        self.user_types = {t.name: t.id for t in tenant.user_types.values()}
        self.logins = {u.login: u.id for u in tenant.users}

    @staticmethod
    def suggest(phrase: str, names: dict[str, str], n: int = 3) -> list[str]:
        """Closest known names to a phrase (case-insensitive fuzzy match)."""
        lowered = {k.lower(): k for k in names}
        hits = difflib.get_close_matches(phrase.lower(), list(lowered), n=n, cutoff=0.6)
        return [lowered[h] for h in hits]

    def suggest_from_text(self, text: str, names: dict[str, str], n: int = 3) -> list[str]:
        """Closest known names to any 1-4 word window of the text."""
        words = re.findall(r"[\w()&/.-]+", text)
        cands: dict[str, float] = {}
        for i in range(len(words)):
            for j in range(i + 1, min(i + 5, len(words) + 1)):
                phrase = " ".join(words[i:j]).lower()
                for name in names:
                    r = difflib.SequenceMatcher(None, phrase, name.lower()).ratio()
                    if r >= 0.75 and r > cands.get(name, 0.0):
                        cands[name] = r
        return [k for k, _ in sorted(cands.items(), key=lambda kv: -kv[1])[:n]]

    @staticmethod
    def find_all(text: str, names: dict[str, str]) -> list[tuple[int, int, str]]:
        """All (start, end, name) occurrences of names in text, longest names first, non-overlapping."""
        found: list[tuple[int, int, str]] = []
        taken: list[tuple[int, int]] = []
        for name in sorted(names, key=len, reverse=True):
            if len(name) < 2:
                continue
            for m in re.finditer(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", text, re.I):
                span = (m.start(), m.end())
                if any(not (span[1] <= a or span[0] >= b) for a, b in taken):
                    continue
                taken.append(span)
                found.append((span[0], span[1], name))
        return sorted(found)


# ------------------------------------------------------------------------------------------ parsing


def _app_id(tenant: Tenant, label: str) -> str:
    return next(a.id for a in tenant.apps.values() if a.label == label)


def parse_invariant(sentence: str, tenant: Tenant) -> ParsedInvariant:  # noqa: C901 - a grammar is branchy by nature
    text = " ".join(sentence.strip().rstrip(".").split())
    names = _Names(tenant)
    notes: list[str] = []
    problems: list[str] = []
    when: dict[str, Any] = {}
    expect: dict[str, Any] = {}
    apps: list[str] = []
    policy: str | None = None
    all_apps = False
    negated_capability = False
    with_session = bool(_SESSION.search(text))
    if with_session:
        text = _SESSION.sub("", text).strip()

    # --- apps / policies -----------------------------------------------------------------------
    app_hits = names.find_all(text, names.apps)
    apps = [name for _, _, name in app_hits]
    consumed = [(a, b) for a, b, _ in app_hits]
    pol_hits = [
        h
        for h in names.find_all(text, names.policies)
        if not any(not (h[1] <= a or h[0] >= b) for a, b in consumed)
    ]
    if pol_hits and not apps:
        policy = pol_hits[0][2]
        consumed.append((pol_hits[0][0], pol_hits[0][1]))
    if _ALL_APPS.search(text):
        all_apps = True
    if not apps and not policy and not all_apps:
        msg = "no app or policy recognised: name an app label (e.g. 'Salesforce'), a policy, or say 'any app'"
        close = names.suggest_from_text(text, names.apps) or names.suggest_from_text(text, names.policies)
        if close:
            msg += "; did you mean " + " / ".join(repr(c) for c in close) + "?"
        problems.append(msg)

    def strip_consumed(t: str) -> str:
        out = list(t)
        for a, b in consumed:
            for i in range(a, b):
                out[i] = " "
        return "".join(out)

    rest = strip_consumed(text)

    # --- rule names and attribute literals (consumed first: they may contain group/zone words) -------
    rule_names = {
        r.name
        for pol in tenant.access_policies
        if all_apps
        or pol.name == policy
        or any(tenant.apps[_app_id(tenant, ap)].access_policy_id == pol.id for ap in apps)
        for r in pol.rules
    }
    rule_expect: dict[str, Any] = {}
    m_any = _RULE_ANY.search(rest)
    if m_any:
        rule_expect["rules_any"] = [next(g for g in m_any.groups() if g).strip()]
        consumed.append((m_any.start(), m_any.end()))
    m_none = _RULE_NONE.search(rest)
    if m_none:
        rule_expect["rules_none"] = [next(g for g in m_none.groups() if g).strip()]
        consumed.append((m_none.start(), m_none.end()))
    for key in ("rules_any", "rules_none"):
        for rname in rule_expect.get(key, []):
            if rule_names and rname not in rule_names:
                msg = f"rule {rname!r} is not a rule of the policy governing {', '.join(apps) or policy or 'these apps'}"
                close = names.suggest(rname, {r: r for r in rule_names})
                if close:
                    msg += "; did you mean " + " / ".join(repr(c) for c in close) + "?"
                problems.append(msg)
    attr = re.search(
        r"whose (\w+) (?:is|equals|=) ['\"]?([^'\"]+?)['\"]?(?:\s|$)|with (\w+) (?:set to |of |= )['\"]?([^'\"]+?)['\"]?(?:\s|$)",
        rest,
        re.I,
    )
    if attr:
        k = attr.group(1) or attr.group(3)
        v = attr.group(2) or attr.group(4)
        when["attributes"] = {f"user.{k}": v}
        consumed.append((attr.start(), attr.end()))
    rest = strip_consumed(text)

    # --- context: zones ------------------------------------------------------------------------
    zone_hits = names.find_all(rest, names.zones)
    zones_in: list[str] = []
    zones_out: list[str] = []
    for a, _b, zname in zone_hits:
        before = rest[max(0, a - 40) : a].lower()
        negative = bool(
            re.search(
                r"(outside|not (?:on|in|from|connected to)|off|away from|other than|except|unless|from anywhere but)\s*(?:the |of )?$",
                before,
            )
        )
        # "or"-joined zones inherit the polarity of the first one in the phrase
        if not negative and zones_out and re.search(r"(?:or|,|nor)\s*(?:the )?$", before):
            negative = True
        (zones_out if negative else zones_in).append(zname)
    unless = _UNLESS.search(rest)
    unless_zones: list[str] = []
    if unless and zones_in and not zones_out:
        # zones named after "unless" belong to the exception; polarity is decided once we know the requirement
        unless_pos = unless.start()
        unless_zones = [z for a, _b, z in zone_hits if a > unless_pos]
        zones_in = [z for z in zones_in if z not in unless_zones]
    if _INTERNET.search(rest):
        zones_out = list(names.zones) if names.zones else zones_out
        notes.append("'from the internet' read as: inside none of the org's network zones")
    if zones_in:
        when["zones_any"] = zones_in
    if zones_out:
        when["zones_none"] = zones_out
    for a, b, _ in zone_hits:
        consumed.append((a, b))
    rest = strip_consumed(text)

    # --- context: device / risk / assurance / platform ---------------------------------------------
    if _UNMANAGED.search(rest):
        when["managed"] = False
    elif _MANAGED.search(rest):
        when["managed"] = True
    if _UNREGISTERED.search(rest):
        when["registered"] = False
    elif _REGISTERED.search(rest) and "managed" not in when:
        when["registered"] = True
    plats = [
        p for k, p in _PLATFORMS.items() if re.search(r"(?<![\w-])" + re.escape(k) + r"(?![\w-])", rest, re.I)
    ]
    if plats:
        when["platforms_any"] = sorted({p.value for p in plats})
    da_hits = names.find_all(rest, names.assurances)
    if da_hits:
        when["assurance_any"] = [n for _, _, n in da_hits]
        for a, b, _ in da_hits:
            consumed.append((a, b))
        rest = strip_consumed(text)
    rm = _RISK.search(rest)
    if rm:
        when["risk"] = next(g for g in rm.groups() if g).upper()
    ut_hits = [
        h
        for h in names.find_all(rest, names.user_types)
        if re.search(r"user type|type of user|typed", rest, re.I)
    ]
    if ut_hits:
        when["user_types_any"] = [n for _, _, n in ut_hits]

    # --- subject: groups / users ----------------------------------------------------------------------
    group_hits = names.find_all(rest, names.groups)
    groups_any: list[str] = []
    groups_none: list[str] = []
    for a, _b, gname in group_hits:
        before = rest[max(0, a - 40) : a].lower()
        negative = bool(
            re.search(
                r"(not (?:in|members? of|part of)|outside(?: of)?|except(?: for)?|other than|who are not (?:in )?|non-)\s*(?:the |of )?$",
                before,
            )
        )
        if not negative and groups_none and re.search(r"(?:or|,|nor|and)\s*(?:the )?$", before):
            negative = True
        (groups_none if negative else groups_any).append(gname)
    only_subject = _ONLY_SUBJECT.match(text)
    if only_subject and groups_any:
        # "Only Finance can access Payroll" => users NOT in Finance are denied
        groups_none, groups_any = groups_any, []
        expect["access"] = "DENY"
        notes.append("'only <group> can …' read as: everyone who is not in that group is denied")
    login_hits = names.find_all(rest, names.logins)
    if login_hits:
        when["users_any"] = [n for _, _, n in login_hits]
    if groups_any:
        if re.search(r"\b(?:who are|that are|and) also\b|\bboth\b", rest, re.I) and len(groups_any) > 1:
            when["groups_all"] = groups_any
            notes.append("groups joined with 'both/also' read as: members of all of them")
        else:
            when["groups_any"] = groups_any
    if groups_none:
        when["groups_none"] = groups_none
    nobody = bool(_NOBODY.match(text))
    if nobody:
        negated_capability = True
    elif (
        not groups_any
        and not login_hits
        and not _EVERYONE.match(text)
        and not only_subject
        and not groups_none
        and "attributes" not in when
        and "user_types_any" not in when
    ):
        # subject words that are not a known group
        subj = re.match(
            r"^(?:members of |users in |the )?([A-Za-z][\w &/-]{1,40}?)(?: members| users| group)?\s+(?:can|must|cannot|can't|may|should|shall|are|is|need|on|from|with|outside|inside)\b",
            rest,
            re.I,
        )
        if subj:
            cand = subj.group(1).strip()
            cand_words = [w for w in re.findall(r"[A-Za-z][\w-]*", cand)]
            context_only = all(
                _CONTEXT_SUBJECT.fullmatch(w)
                or _RISK.search(w)
                or _UNMANAGED.search(w)
                or _MANAGED.search(w)
                or _REGISTERED.search(w)
                or w.lower() in _PLATFORMS
                or w.lower()
                in {
                    "on",
                    "from",
                    "with",
                    "to",
                    "the",
                    "a",
                    "an",
                    "of",
                    "in",
                    "and",
                    "or",
                    "high",
                    "low",
                    "medium",
                    "risk",
                    "unknown",
                    "new",
                }
                for w in cand_words
            )
            if cand_words and not context_only:
                msg = (
                    f"'{cand}' is not a group, user or user type in the snapshot "
                    "(groups are matched by exact name, case-insensitively)"
                )
                close = names.suggest(cand, names.groups) or names.suggest_from_text(cand, names.groups)
                if close:
                    msg += "; did you mean " + " / ".join(repr(c) for c in close) + "?"
                problems.append(msg)

    # --- expectation ----------------------------------------------------------------------------------
    if _DENY_PHRASES.search(text) and not re.search(
        r"cannot|can't|can not|may not|never be able to", text, re.I
    ):
        expect.setdefault("access", "DENY")
    if re.search(
        r"cannot|can't|can not|may not|must not be able to|should not be able to|never be able to|are not allowed to|is not allowed to",
        text,
        re.I,
    ):
        negated_capability = True
    strength_req: Strength | None = None
    for pat, strength in _STRENGTH_PHRASES:
        if re.search(pat, text, re.I):
            strength_req = strength
            break
    password_only = bool(_PASSWORD_ONLY.search(text))
    passwordless = bool(_PASSWORDLESS.search(text))
    if negated_capability:
        # "X cannot access A with only a password" => every path needs more than a password
        if password_only:
            expect["min_strength"] = Strength.ONE_FA_POSSESSION.name
            notes.append(
                "'with only a password' read literally: a single non-password factor would still satisfy this; say 'must use MFA' to require two factor types"
            )
        elif passwordless:
            expect["passwordless"] = False
        elif strength_req is not None and re.search(
            r"without|less than|weaker than|anything (?:less|weaker)", text, re.I
        ):
            expect["min_strength"] = strength_req.name
        else:
            expect.setdefault("access", "DENY")
    else:
        if strength_req is not None and re.search(
            r"must|need|require|should|have to|has to|only with|always", text, re.I
        ):
            expect["min_strength"] = strength_req.name
        if re.search(
            r"must (?:always )?(?:enter|use|provide|type) (?:a |their )?password|password[- ]?(?:is )?required|password plus|password and (?:a |another )?(?:second )?factor",
            text,
            re.I,
        ):
            expect["password_required"] = True
        if _ALLOW_PHRASES.search(text) and not expect:
            expect["access"] = "ALLOW"
    expect.update(rule_expect)
    can_only = _CAN_ONLY_FROM.search(text)
    if can_only and not expect:
        expect["access"] = "DENY"
        if not zones_out and zones_in:
            when.pop("zones_any", None)
            when["zones_none"] = zones_in
        notes.append("'can only … from <zones>' read as: outside those zones the outcome must be DENY")
    if unless_zones:
        if (
            expect.get("access") == "DENY"
            or negated_capability
            or "min_strength" in expect
            or "passwordless" in expect
            or "password_required" in expect
        ):
            # "must be denied / cannot access / must use MFA … unless on the VPN": requirement applies outside
            when.setdefault("zones_none", []).extend(
                z for z in unless_zones if z not in when.get("zones_none", [])
            )
            if not when.get("zones_any"):
                when.pop("zones_any", None)
            notes.append("'unless on/from <zone>' read as: the requirement applies outside those zones")
        else:
            # "Sales can access Salesforce unless they are on the VPN": inside the zone the outcome must be DENY
            when["zones_any"] = unless_zones
            expect["access"] = "DENY"
            notes.append(
                "'can access … unless on <zone>' read as: inside those zones the outcome must be DENY"
            )
    if when.get("zones_any") == []:
        when.pop("zones_any")
    if not expect:
        problems.append(
            "no requirement recognised: say e.g. 'must be denied', 'cannot access', 'must be able to access', "
            "'must use MFA', 'must use phishing-resistant MFA', 'cannot … with only a password', "
            "'must not be able to sign in without a password', 'must be handled by rule …'"
        )

    if problems:
        return ParsedInvariant(sentence, None, "", problems, notes)

    name = re.sub(r"[^a-z0-9]+", "-", sentence.lower()).strip("-")[:60] or "invariant"
    assertion = Assertion(
        name=name,
        description=sentence.strip(),
        apps=apps,
        policy=policy,
        all_apps=all_apps and not apps and not policy,
        when=when,
        expect=expect,
        with_session_policy=with_session,
    )
    return ParsedInvariant(sentence, assertion, reading(assertion, tenant), [], notes)


# ------------------------------------------------------------------------------------------ restatement


def reading(a: Assertion, tenant: Tenant) -> str:
    """Formal, unambiguous restatement of an assertion in English."""
    scope = (
        "every app"
        if a.all_apps
        else (", ".join(a.apps) if a.apps else f"apps governed by policy {a.policy!r}")
    )
    prem: list[str] = []
    w = a.when
    if "groups_any" in w:
        prem.append("is a member of " + " or ".join(w["groups_any"]))
    if "groups_all" in w:
        prem.append("is a member of " + " and ".join(w["groups_all"]))
    if "groups_none" in w:
        prem.append("is not a member of " + " nor ".join(w["groups_none"]))
    if "users_any" in w:
        prem.append("is " + " or ".join(w["users_any"]))
    if "user_types_any" in w:
        prem.append("has user type " + " or ".join(w["user_types_any"]))
    if "attributes" in w:
        prem.append(", ".join(f"has {k} = {v!r}" for k, v in w["attributes"].items()))
    ctx: list[str] = []
    if "zones_any" in w:
        ctx.append("from inside " + " or ".join(w["zones_any"]))
    if "zones_none" in w:
        ctx.append("from outside " + " and ".join(w["zones_none"]))
    if "managed" in w:
        ctx.append("on a managed device" if w["managed"] else "on an unmanaged device")
    if "registered" in w:
        ctx.append("on a registered device" if w["registered"] else "on an unregistered device")
    if "platforms_any" in w:
        ctx.append("on " + "/".join(w["platforms_any"]))
    if "assurance_any" in w:
        ctx.append("on a device satisfying " + " or ".join(w["assurance_any"]))
    if "risk" in w:
        ctx.append(f"with Okta risk level {w['risk'] if isinstance(w['risk'], str) else '/'.join(w['risk'])}")
    subject = "every user who " + " and ".join(prem) if prem else "every user"
    context = " ".join(ctx) if ctx else "in every context (any network, device, platform, risk level)"
    e = a.expect
    req: list[str] = []
    if e.get("access") == "DENY":
        req.append("the deciding rule is DENY (or no rule matches)")
    if e.get("access") == "ALLOW":
        req.append("the deciding rule is ALLOW")
    if "min_strength" in e:
        req.append(
            f"the weakest authentication the deciding rule accepts is at least {Strength[e['min_strength']].label} (a DENY also satisfies this)"
        )
    if "max_strength" in e:
        req.append(f"the deciding rule requires at most {Strength[e['max_strength']].label}")
    if e.get("passwordless") is False:
        req.append("no accepted authentication path avoids the password")
    if e.get("password_required"):
        req.append("every accepted authentication path includes the password")
    if "rules_any" in e:
        req.append("the deciding rule is one of " + ", ".join(repr(x) for x in e["rules_any"]))
    if "rules_none" in e:
        req.append("the deciding rule is none of " + ", ".join(repr(x) for x in e["rules_none"]))
    tail = " (judged after adding the global session policy's requirements)" if a.with_session_policy else ""
    return f"For {subject}, {context}, accessing {scope}: {'; and '.join(req)}{tail}."


# ------------------------------------------------------------------------------------------ checking


def check_invariants(analyzer: Analyzer, sentences: list[str]) -> list[InvariantResult]:
    checker = AssertionChecker(analyzer)
    out: list[InvariantResult] = []
    for sentence in sentences:
        parsed = parse_invariant(sentence, analyzer.t)
        results = checker.check(parsed.assertion) if parsed.assertion else []
        assumptions = sorted(set(analyzer.u.assumptions) | set(analyzer.catalogue.warnings))
        out.append(InvariantResult(parsed, results, assumptions))
    return out


def explain_result(res: InvariantResult, tenant: Tenant) -> list[str]:
    """Human-readable lines for one invariant result."""
    lines = [f"{res.verdict}: {res.parsed.sentence}"]
    if res.parsed.problems:
        lines += [f"  cannot read this sentence: {p}" for p in res.parsed.problems]
        return lines
    lines.append(f"  reading: {res.parsed.reading}")
    for n in res.parsed.notes:
        lines.append(f"  note: {n}")
    for r in res.results:
        if r.error:
            lines.append(f"  error ({r.policy.name}): {r.error}")
        elif r.vacuous:
            lines.append(
                f"  {r.policy.name}: vacuous — the premise matches no user/context (check group and zone names)"
            )
        elif r.holds:
            lines.append(f"  {r.policy.name}: holds for every user and context")
        else:
            lines.append(f"  {r.policy.name}: VIOLATED by rule {r.violating_rule!r} → {r.violating_outcome}")
            if r.counterexample:
                lines.append(f"    counterexample: {r.counterexample}")
            for w_ in r.who[:6]:
                lines.append(f"    who (in some context): {w_}")
    if res.verdict == "PROVED" and res.assumptions:
        lines.append("  proof relies on these modelling assumptions:")
        lines += [f"    - {a}" for a in res.assumptions]
    return lines
