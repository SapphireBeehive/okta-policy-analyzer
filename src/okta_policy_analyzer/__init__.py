"""okta-policy-analyzer: formal verification of Okta authentication policies.

Ingests every Okta policy and rule, models all groups and contexts symbolically, and uses the z3 SMT
solver (with an optional TLA+ export) to state exactly who can do what form of authentication.
"""

__version__ = "0.1.0"
