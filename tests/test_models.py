"""Tests for the Pydantic evidence-grounded output models."""

from src.models import MitreFinding, Recommendation, StructuredFindings


def test_confidence_coercion():
    assert MitreFinding(confidence="high").confidence == 0.9
    assert MitreFinding(confidence="85%").confidence == 0.85
    assert MitreFinding(confidence=0.42).confidence == 0.42
    assert MitreFinding(confidence="nonsense").confidence == 0.5


def test_finding_defaults_and_evidence():
    f = MitreFinding(technique_id="T1110.001", evidence_refs=["EVT-0004"])
    assert f.evidence_refs == ["EVT-0004"]
    assert f.verified is False
    assert 0.0 <= f.confidence <= 1.0


def test_structured_findings_parses_dict():
    data = {
        "findings": [{"technique_id": "T1190", "confidence": 0.7,
                      "evidence_refs": ["EVT-0009"]}],
        "recommendations": [{"action": "Block IP", "priority": "immediate",
                             "evidence_refs": ["EVT-0009"]}],
    }
    sf = StructuredFindings.model_validate(data)
    assert sf.findings[0].technique_id == "T1190"
    assert isinstance(sf.recommendations[0], Recommendation)
