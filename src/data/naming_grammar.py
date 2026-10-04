"""
Naming-grammar classification.

Provenance
----------
`COMPOUND_SUFFIXES` / `COMPOUND_PREFIXES` are ported verbatim from the
prior notebook's Cell 18. There, they drove candidate GENERATION (build
plausible-but-fake compound names to probe against live registries).
Here, the same lists drive candidate CLASSIFICATION (does this observed,
real, already-registered name match a predictable hallucination-prone
grammar pattern?). This is the exact repurposing described in the research
proposal: "run it in reverse over your existing confirmed_fake and the
incident corpus to assign each a grammar-match label."

This module is the direct implementation of H1's independent variable
(`grammar_match`). Per the Phase 0 audit, it MUST be computed without any
reference to injection labels, malicious labels, or documentation content
— it looks at the name string only. Do not extend this module to accept
any label or document-derived input; that would make H1 circular.

The typosquat generator (`generate_typosquat_candidates`) is also ported
from Cell 12, kept as a utility for future candidate-generation needs
(e.g., building synthetic negative controls). It is NOT part of the core
H1 pipeline and is not required for Phase 1.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Ported verbatim from notebook Cell 18.
COMPOUND_SUFFIXES = [
    "cli", "core", "tools", "utils", "sdk", "client", "server",
    "plugin", "hotfix", "cloud", "test", "testing", "dev",
    "config", "api", "extension", "language-server", "language",
]

# Ported verbatim from notebook Cell 18.
COMPOUND_PREFIXES = [
    "py", "node", "react", "vue", "aws", "azure", "google", "dagster",
    "pandas", "django", "flask", "express",
]

# New for this pivot, not in the original notebook: the "trend" suffixes
# named explicitly in the research proposal's own examples (-turbo/-pro/
# -plus) are LLM-hallucination-flavored rather than legitimate-compound-
# package-flavored. Kept as a separate list because conflating the two
# would blur exactly the distinction H1 needs — "legitimate compound
# naming" (Cell 18's original purpose: reduce false positives against real
# packages like `pytest-mock-server`) is a different thing from
# "hallucination-trend naming" (packages an LLM would plausibly invent
# because the pattern SOUNDS like a real product tier/version, e.g.
# `openai-turbo`, `requests-pro`). Both are tracked, separately labeled.
TREND_SUFFIXES = [
    "turbo", "pro", "plus", "ai", "ml", "premium", "enterprise", "max",
]


@dataclass
class GrammarMatch:
    name: str
    matched_compound_suffixes: list[str] = field(default_factory=list)
    matched_compound_prefixes: list[str] = field(default_factory=list)
    matched_trend_suffixes: list[str] = field(default_factory=list)
    is_grammar_flagged: bool = False
    matched_pattern_type: str = "none"  # 'compound' | 'trend' | 'both' | 'none'

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "matched_compound_suffixes": self.matched_compound_suffixes,
            "matched_compound_prefixes": self.matched_compound_prefixes,
            "matched_trend_suffixes": self.matched_trend_suffixes,
            "is_grammar_flagged": self.is_grammar_flagged,
            "matched_pattern_type": self.matched_pattern_type,
        }


def _normalize(name: str) -> str:
    """Same normalization implicitly used by the original notebook's
    string-matching (lowercase, treat @scope/ and separators uniformly)."""
    return name.lower().replace("@", "").replace("/", "-")


def classify_naming_grammar(name: str) -> GrammarMatch:
    """
    Classifies an OBSERVED, already-registered artifact name against the
    hand-coded grammar (Phase 3's "Baseline A" in the audited plan).

    Deliberately simple substring/suffix matching — same approach as the
    original notebook's candidate generator, just run in the opposite
    direction. Statistical features (n-grams, entropy, edit distance —
    Phase 3's "Baseline B") are a separate module, not this one, per the
    audit's requirement that hand-coded and statistical grammar signals be
    distinguishable in ablations.
    """
    norm = _normalize(name)
    parts = [p for p in norm.replace("_", "-").split("-") if p]

    matched_compound_suffixes = [s for s in COMPOUND_SUFFIXES if s in parts]
    matched_compound_prefixes = [p for p in COMPOUND_PREFIXES if p in parts]
    matched_trend_suffixes = [s for s in TREND_SUFFIXES if s in parts]

    has_compound = bool(matched_compound_suffixes or matched_compound_prefixes)
    has_trend = bool(matched_trend_suffixes)

    if has_compound and has_trend:
        pattern_type = "both"
    elif has_trend:
        pattern_type = "trend"
    elif has_compound:
        pattern_type = "compound"
    else:
        pattern_type = "none"

    return GrammarMatch(
        name=name,
        matched_compound_suffixes=matched_compound_suffixes,
        matched_compound_prefixes=matched_compound_prefixes,
        matched_trend_suffixes=matched_trend_suffixes,
        is_grammar_flagged=has_compound or has_trend,
        matched_pattern_type=pattern_type,
    )


def classify_batch(names: list[str]) -> list[GrammarMatch]:
    return [classify_naming_grammar(n) for n in names]


# ---------------------------------------------------------------------
# Typosquat / composite candidate generation.
# Ported from notebook Cell 12. Not required for Phase 1's core H1 path;
# kept as a utility. Uses a pure-Python Levenshtein distance fallback
# instead of a hard `rapidfuzz` dependency, since Phase 0's dependency
# policy is "minimal dependencies" and this function is not on the
# critical path.
# ---------------------------------------------------------------------

def _levenshtein_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr_row = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr_row[j] = min(
                curr_row[j - 1] + 1,       # insertion
                prev_row[j] + 1,           # deletion
                prev_row[j - 1] + cost,    # substitution
            )
        prev_row = curr_row
    return prev_row[-1]


def generate_typosquat_candidates(
    name: str, real_set: set[str], n: int = 2, seed: int | None = None
) -> list[str]:
    """
    Ported from Cell 12's `generate_typosquats`, with `rapidfuzz.Levenshtein`
    replaced by the pure-Python implementation above (behaviorally
    equivalent for these short package-name strings; rapidfuzz remains
    fine to use instead in an environment where it's installed and speed
    matters — swap `_levenshtein_distance` for `rapidfuzz.distance.
    Levenshtein.distance` if generating candidates at the original
    notebook's scale of thousands of names).
    """
    import random

    rng = random.Random(seed)
    mutations: set[str] = set()
    alphabet = "abcdefghijklmnopqrstuvwxyz-_"

    for i in range(len(name)):
        for c in alphabet:
            mutations.add(name[:i] + c + name[i + 1 :])
    for i in range(len(name)):
        mutations.add(name[:i] + name[i + 1 :])
    for i in range(len(name) + 1):
        for c in alphabet:
            mutations.add(name[:i] + c + name[i:])
    for i in range(len(name) - 1):
        s = list(name)
        s[i], s[i + 1] = s[i + 1], s[i]
        mutations.add("".join(s))

    filtered = [
        m
        for m in mutations
        if m not in real_set
        and 1 <= _levenshtein_distance(m, name) <= 2
        and 2 <= len(m) <= 60
        and m
    ]
    return rng.sample(filtered, min(n, len(filtered)))
