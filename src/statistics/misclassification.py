"""
Outcome-misclassification correction of a 2x2 odds ratio from measured
predictive values (research_log 5.19).

The labeler's validation gives predictive values, not sensitivity and
specificity: precision (PPV) on a sample of labeler positives and the miss
rate (1 - NPV) on a sample of labeler negatives. The simple bias analysis
for that design back-calculates the expected true outcome in each exposure
row (Lash, Fox & Fink, *Applying Quantitative Bias Analysis to Epidemiologic
Data*, 2nd ed., 2021, ch. 6, predictive-value approach):

    true positives in a row = labeler positives * PPV
                              + eligible labeler negatives * miss rate

"Eligible" negatives are those the miss rate was measured on; negatives
outside that frame (here: no-text campaigns, which have no text to miss
anything in) get a miss rate of 0. The method assumes the predictive values
are the same in both exposure rows (non-differential predictive values).

probabilistic_correction() repeats the correction with PPV and miss rate
drawn from Jeffreys Beta(k + 1/2, n - k + 1/2) posteriors and adds random
error on the log odds ratio (Woolf SE of the corrected table): a
probabilistic bias analysis interval that covers both validation
uncertainty and sampling error.
"""

from __future__ import annotations

import math
import random


def corrected_table(table: list[list[float]], ppv: float, miss_rate: float,
                    no_text_negatives: tuple[float, float] = (0, 0)) -> list[list[float]]:
    """`table` is [[exposed & outcome, exposed & not], [unexposed & outcome,
    unexposed & not]] (ContingencyTable.as_2x2 order). `no_text_negatives`
    gives, per row, labeler negatives outside the miss-rate frame."""
    out = []
    for (pos, neg), excluded in zip(table, no_text_negatives):
        if excluded > neg:
            raise ValueError("more excluded negatives than negatives")
        true_pos = pos * ppv + (neg - excluded) * miss_rate
        out.append([true_pos, pos + neg - true_pos])
    return out


def odds_ratio(table: list[list[float]]) -> float | None:
    (a, b), (c, d) = table
    return (a * d) / (b * c) if b * c > 0 else None


def woolf_ci(table: list[list[float]], z: float = 1.959963984540054) -> tuple[float, float] | None:
    (a, b), (c, d) = table
    if min(a, b, c, d) <= 0:
        return None
    se = math.sqrt(1 / a + 1 / b + 1 / c + 1 / d)
    lor = math.log(odds_ratio(table))
    return (math.exp(lor - z * se), math.exp(lor + z * se))


def simple_correction(table, ppv: float, miss_rate: float, no_text_negatives=(0, 0)) -> dict:
    t = corrected_table(table, ppv, miss_rate, no_text_negatives)
    return {"ppv": ppv, "miss_rate": miss_rate, "corrected_table": [[round(x, 3) for x in r] for r in t],
            "odds_ratio": odds_ratio(t), "woolf_ci_on_corrected_table": woolf_ci(t)}


def _percentile(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    i = q * (len(xs) - 1)
    lo, hi = math.floor(i), math.ceil(i)
    return xs[lo] + (xs[hi] - xs[lo]) * (i - lo)


def probabilistic_correction(table, ppv_k: int, ppv_n: int, miss_k: int, miss_n: int,
                             no_text_negatives=(0, 0), draws: int = 20000, seed: int = 20261006) -> dict:
    rng = random.Random(seed)
    ors, skipped = [], 0
    for _ in range(draws):
        ppv = rng.betavariate(ppv_k + 0.5, ppv_n - ppv_k + 0.5)
        miss = rng.betavariate(miss_k + 0.5, miss_n - miss_k + 0.5)
        t = corrected_table(table, ppv, miss, no_text_negatives)
        (a, b), (c, d) = t
        if min(a, b, c, d) <= 0:
            skipped += 1
            continue
        se = math.sqrt(1 / a + 1 / b + 1 / c + 1 / d)
        ors.append(math.exp(math.log(a * d / (b * c)) + rng.gauss(0, se)))
    return {"method": "probabilistic bias analysis: Jeffreys Beta draws for PPV and miss rate, "
                      "plus random error N(0, Woolf SE^2) on the corrected log OR",
            "draws": draws, "seed": seed, "skipped_draws": skipped,
            "median_or": _percentile(ors, 0.5),
            "interval_95": (_percentile(ors, 0.025), _percentile(ors, 0.975))}
