# Injection-Payload Annotation Guidelines

## Purpose

This document guides HUMAN review of `heuristic_label` candidates produced
by `src/labeling/injection_labeler.py`. The heuristic labeler is a
transparent pattern-matcher, not ground truth — every record it flags
(`injection_present_candidate: true`) needs a human decision: confirm,
reject, or recategorize.

## Primary label

`injection_present ∈ {0, 1}` — final, human-confirmed.

## Secondary label

`injection_type` — one of the 10 categories in
`src/labeling/injection_taxonomy.py`, or `benign_instruction_like` if the
heuristic flagged it but a human determines it's not actually an
injection attempt.

## The core question to ask for every flagged record

**"Is this text trying to get an AI/agent to do something the package's
own documented functionality doesn't call for?"**

If yes → `injection_present = 1`, pick the matching category.
If no → `injection_present = 0`, category = `benign_instruction_like`.

## Category definitions, examples, and ambiguity rules

See `src/labeling/injection_taxonomy.py::TAXONOMY` for the authoritative,
version-controlled definitions — each category there carries:
- `definition`
- `positive_examples`
- `negative_examples`
- `ambiguity_notes` (the specific judgment calls annotators will hit)

Do not duplicate that content here by hand; it will drift out of sync.
Read it directly from the module (or render it via
`generate_annotation_reference()` once that's added) before annotating.

## Edge cases annotators will actually hit

1. **README badges/CI config that mention "run" or "execute."** Almost
   always benign — CI/build instructions are not agent-directed. Default
   to `benign_instruction_like` unless there's a clear agent/AI audience
   marker.

2. **Legitimate post-install scripts (native extension compilation).**
   Extremely common, not injection. Only escalate if paired with
   obfuscation (base64-encoded commands, non-standard download domains)
   or an explicit "don't tell the user" framing.

3. **Security advisories that DESCRIBE an injection attack in their
   `description` field** (i.e., the advisory text is explaining what the
   malicious package did, written in third person by a security
   researcher) vs. **the malicious package's own README containing the
   actual injection text verbatim.** Both should be labeled
   `injection_present = 1` if a real injection existed, but note which
   case it is in the annotation record — this matters for later temporal
   analysis (was the payload IN the artifact, or only reported about it).

4. **GHSA/OSV `description` fields quoting the malicious code.** These are
   the most information-dense records — the advisory text itself often
   contains the injection payload as a code excerpt for documentation
   purposes. Label based on whether a real payload existed, not on
   whether the advisory used exact-match phrasing from the taxonomy
   patterns.

## Independence requirement (do not skip this)

While annotating, DO NOT look at the package name or its
`grammar_match`/naming-grammar classification before making your
`injection_present` decision. If you're annotating from a spreadsheet
export, hide the `name` and `grammar_match` columns. This is not a
suggestion — H1 is invalid if naming information influences injection
labeling, per the Phase 0 audit.

## Inter-annotator agreement

For any batch used in a primary (non-exploratory) analysis, at least two
independent passes are required, with Cohen's κ computed on the overlap.
Target κ ≥ 0.60 (substantial agreement) before treating a batch as usable
for H1. Below that, revise these guidelines and re-annotate a fresh
sample — don't just average over disagreement.

## LLM-assisted annotation (if used later)

If an LLM is used as a second annotator (not yet implemented in this
codebase), record for every call:
- exact prompt text
- model name/version
- temperature
- date
- raw output
- human validation result (agree/disagree/uncertain)

LLM output is a second opinion to reconcile against human judgment, not a
substitute for it.
