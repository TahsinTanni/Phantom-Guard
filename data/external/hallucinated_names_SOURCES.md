# hallucinated_names.txt — provenance

Format: `<ecosystem>\t<name>\t<hallucination_count>` (tab-separated, one per line).

Source: Churilov, A. (2026). "The Range Shrinks, the Threat Remains: Re-evaluating
LLM Package Hallucinations on the 2026 Frontier-Model Cohort." arXiv:2605.17062.
Files `disclosure/pypi_universal_hallucinations.csv` (121 names) and
`disclosure/npm_universal_hallucinations.csv` (18 names) from the tagged release
`v0.2-preprint` of https://github.com/churik5/slopsquatting-replication-2026
(Zenodo mirror DOI 10.5281/zenodo.19859120). Retrieved 2026-10-03.

License: CC-BY-4.0 (repository LICENSE-DATA). Cite the paper when using.

"Universal" = hallucinated by all five models evaluated in that study; the count
column is the summed hallucination frequency across models. The paper's full
corpus is larger; this is the publicly disclosed subset.
