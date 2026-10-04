import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.data.leakage_checks import (
    check_duplicate_leakage,
    check_name_family_leakage,
    check_temporal_leakage,
    check_label_leakage_correlation,
    check_documentation_version_leakage,
    assert_no_severe_leakage,
)


def test_duplicate_leakage_detects_overlap():
    report = check_duplicate_leakage(["a", "b", "c"], ["c", "d"])
    assert report.severity == "severe"
    assert report.n_violations == 1
    assert "c" in report.details


def test_duplicate_leakage_clean():
    report = check_duplicate_leakage(["a", "b"], ["c", "d"])
    assert report.severity == "none"
    assert not report  # __bool__ is False when no leakage


def test_name_family_leakage_detects_trend_suffix_collision():
    report = check_name_family_leakage(
        train_names=["react-turbo", "vue-helper"],
        test_names=["react-pro", "angular-cli"],
    )
    # 'react-turbo' and 'react-pro' should collapse to family key 'react'
    assert report.severity == "warning"
    assert "react" in report.details


def test_name_family_leakage_clean_when_distinct():
    report = check_name_family_leakage(
        train_names=["react-turbo"], test_names=["totally-different-lib"]
    )
    assert report.severity == "none"


def test_temporal_leakage_detects_future_feature():
    records = [
        {
            "pred_time": "2025-01-01T00:00:00+00:00",
            "download_count_time": "2025-06-01T00:00:00+00:00",  # future!
        }
    ]
    report = check_temporal_leakage(
        records, "pred_time", ["download_count_time"]
    )
    assert report.severity == "severe"
    assert report.n_violations == 1


def test_temporal_leakage_clean_when_feature_precedes_prediction():
    records = [
        {
            "pred_time": "2025-06-01T00:00:00+00:00",
            "download_count_time": "2025-01-01T00:00:00+00:00",
        }
    ]
    report = check_temporal_leakage(
        records, "pred_time", ["download_count_time"]
    )
    assert report.severity == "none"


def test_label_leakage_correlation_flags_perfect_correlation():
    naming_features = {"suspicious_feature": [0, 0, 1, 1, 1, 0, 1, 1]}
    injection_labels = [0, 0, 1, 1, 1, 0, 1, 1]  # identical -> r = 1.0
    report = check_label_leakage_correlation(naming_features, injection_labels)
    assert report.severity == "warning"
    assert report.n_violations == 1


def test_label_leakage_correlation_clean_when_uncorrelated():
    naming_features = {"name_length": [5, 8, 3, 9, 6, 7, 4, 10]}
    injection_labels = [0, 1, 0, 1, 1, 0, 1, 0]
    report = check_label_leakage_correlation(
        naming_features, injection_labels, correlation_threshold=0.9
    )
    assert report.severity == "none"


def test_documentation_version_leakage_detects_post_incident_snapshot():
    records = [
        {
            "doc_snapshot_time": "2026-03-01T00:00:00+00:00",
            "incident_report_time": "2026-01-01T00:00:00+00:00",
        }
    ]
    report = check_documentation_version_leakage(
        records, "doc_snapshot_time", "incident_report_time"
    )
    assert report.severity == "severe"


def test_assert_no_severe_leakage_raises_on_severe():
    dup_report = check_duplicate_leakage(["x"], ["x"])
    try:
        assert_no_severe_leakage([dup_report])
        assert False, "should have raised"
    except RuntimeError as e:
        assert "SEVERE LEAKAGE" in str(e)


def test_assert_no_severe_leakage_passes_on_warning_only():
    warn_report = check_name_family_leakage(["react-turbo"], ["react-pro"])
    # Should not raise — warning severity is not a hard stop.
    assert_no_severe_leakage([warn_report])
