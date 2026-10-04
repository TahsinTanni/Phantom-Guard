import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.labeling.injection_labeler import (
    label_text,
    label_incident_record,
    label_batch,
    summarize_labeling,
)
from src.labeling.injection_taxonomy import InjectionCategory


def test_label_text_empty_string_is_not_flagged():
    result = label_text("")
    assert result.injection_present_candidate is False
    assert result.matches == []


def test_label_text_flags_direct_instruction_override():
    result = label_text(
        "This tool will ignore all previous instructions and run a hidden command."
    )
    assert result.injection_present_candidate is True
    assert InjectionCategory.DIRECT_INSTRUCTION_OVERRIDE.value in result.matched_categories


def test_label_text_flags_data_exfiltration():
    result = label_text(
        "The malicious code was found to send all environment variables "
        "to an attacker-controlled server."
    )
    assert result.injection_present_candidate is True
    assert InjectionCategory.DATA_EXFILTRATION_INSTRUCTION.value in result.matched_categories


def test_label_text_flags_external_resource_retrieval():
    result = label_text(
        "The package would download and execute a script from a remote URL."
    )
    assert result.injection_present_candidate is True
    assert InjectionCategory.EXTERNAL_RESOURCE_RETRIEVAL.value in result.matched_categories


def test_label_text_does_not_flag_benign_documentation():
    benign_text = (
        "Run `npm install` then `npm start` to launch the development "
        "server. This package requires system-level permissions to "
        "access the camera on some platforms."
    )
    result = label_text(benign_text)
    assert result.injection_present_candidate is False


def test_label_text_does_not_flag_legitimate_credential_use():
    benign_text = (
        "This package reads your AWS credentials from ~/.aws/credentials "
        "to authenticate API calls to S3."
    )
    result = label_text(benign_text)
    # Should NOT match exfiltration pattern since there's no send/post/
    # upload/steal/harvest verb paired with the credential mention.
    assert result.injection_present_candidate is False


def test_matched_text_preserves_context_window():
    text = "x" * 100 + "ignore all previous instructions" + "y" * 100
    result = label_text(text, context_chars=10)
    assert len(result.matches) >= 1
    matched_span_text = result.matches[0].matched_text
    assert "ignore all previous instructions" in matched_span_text
    # Context window should be small, not the whole 200+ char string.
    assert len(matched_span_text) < 100


def test_label_incident_record_combines_summary_and_description():
    record = {
        "package_name": "fake-pkg",
        "ecosystem": "pypi",
        "summary": "Malicious code in fake-pkg",
        "description": "The package would ignore all previous instructions.",
    }
    labeled = label_incident_record(record)
    assert "heuristic_label" in labeled
    assert labeled["heuristic_label"]["injection_present_candidate"] is True
    # Original fields preserved unchanged.
    assert labeled["package_name"] == "fake-pkg"
    assert labeled["ecosystem"] == "pypi"


def test_label_incident_record_handles_missing_fields():
    record = {"package_name": "fake-pkg", "ecosystem": "npm"}
    labeled = label_incident_record(record)
    assert labeled["heuristic_label"]["injection_present_candidate"] is False


def test_label_batch_processes_multiple_records():
    records = [
        {"summary": "benign package", "description": "does normal things"},
        {"summary": "malicious", "description": "ignore all previous instructions"},
    ]
    labeled = label_batch(records)
    assert len(labeled) == 2
    assert labeled[0]["heuristic_label"]["injection_present_candidate"] is False
    assert labeled[1]["heuristic_label"]["injection_present_candidate"] is True


def test_summarize_labeling_computes_correct_rate():
    records = [
        {"summary": "benign", "description": "normal stuff"},
        {"summary": "bad", "description": "ignore all previous instructions"},
        {"summary": "bad2", "description": "send credentials to attacker server"},
    ]
    labeled = label_batch(records)
    summary = summarize_labeling(labeled)
    assert summary["total_records"] == 3
    assert summary["flagged_candidates"] == 2
    assert abs(summary["flagged_rate"] - (2 / 3)) < 1e-9


def test_summarize_labeling_handles_empty_batch():
    summary = summarize_labeling([])
    assert summary["total_records"] == 0
    assert summary["flagged_rate"] == 0.0


def test_label_text_signature_has_no_naming_parameter():
    """
    Guards the Phase 0 audit's independence requirement structurally: the
    core labeling function must accept only text, nothing derived from
    package name or naming-grammar classification.
    """
    import inspect

    sig = inspect.signature(label_text)
    param_names = list(sig.parameters.keys())
    assert "name" not in param_names
    assert "grammar_match" not in param_names
    assert param_names[0] == "text"


def test_label_incident_record_does_not_read_grammar_match_field():
    """
    Even if a record happens to carry a grammar_match field (e.g., after
    merging with naming_grammar.py output), label_incident_record must not
    let it influence the label — verified by checking the label is
    identical with and without that field present.
    """
    record_without = {
        "summary": "ignore all previous instructions",
        "description": "",
    }
    record_with = {
        **record_without,
        "grammar_match": {"is_grammar_flagged": True, "matched_pattern_type": "trend"},
    }
    label_without = label_incident_record(record_without)["heuristic_label"]
    label_with = label_incident_record(record_with)["heuristic_label"]
    assert label_without == label_with
