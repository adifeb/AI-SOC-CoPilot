"""Structured, validated output models for evidence-grounded analysis.

Every finding the tool emits is a typed object that must cite the specific
events it is based on (``evidence_refs`` like ``EVT-0007``) and separates what
was *observed* (facts) from what was *inferred* (inference) from what is
*recommended* (Recommendation). This lets the tool answer
"why did you say this is T1110 - show me the evidence".
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field, field_validator


def _coerce_confidence(v) -> float:
    """Accept 'high'/'medium'/'low', percentages, or 0-1 floats -> 0..1 float."""
    if isinstance(v, str):
        s = v.strip().lower().rstrip("%")
        words = {"high": 0.9, "medium": 0.6, "moderate": 0.6, "low": 0.3}
        if s in words:
            return words[s]
        try:
            f = float(s)
            return round(f / 100, 2) if f > 1 else round(f, 2)
        except ValueError:
            return 0.5
    if isinstance(v, (int, float)):
        return round(v / 100, 2) if v > 1 else round(float(v), 2)
    return 0.5


class MitreFinding(BaseModel):
    """A MITRE ATT&CK technique mapping grounded in evidence."""

    technique_id: str = ""
    technique_name: str = "Unknown"
    tactic: str = "N/A"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    facts: List[str] = Field(default_factory=list)          # observed, from events
    inference: str = ""                                     # the interpretation
    evidence_refs: List[str] = Field(default_factory=list)  # ["EVT-0007", ...]
    verified: bool = False                                  # ID exists in ATT&CK ref

    @field_validator("confidence", mode="before")
    @classmethod
    def _conf(cls, v):
        return _coerce_confidence(v)


class Recommendation(BaseModel):
    """A triage action that must cite the evidence justifying it."""

    action: str = ""
    priority: str = "medium"                                # immediate/high/medium/low
    rationale: str = ""
    evidence_refs: List[str] = Field(default_factory=list)


class StructuredFindings(BaseModel):
    """Top-level container the LLM is asked to return as JSON."""

    findings: List[MitreFinding] = Field(default_factory=list)
    recommendations: List[Recommendation] = Field(default_factory=list)
