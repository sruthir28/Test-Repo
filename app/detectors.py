"""Regex and checksum based detection of personally identifiable information."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern

MAX_TEXT_LENGTH = 100_000


@dataclass(frozen=True)
class Finding:
    """A single piece of PII located in the scanned text."""

    type: str
    value: str
    start: int
    end: int
    confidence: str

    def as_dict(self) -> dict:
        return {
            "type": self.type,
            "value": self.value,
            "start": self.start,
            "end": self.end,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class Detector:
    name: str
    pattern: Pattern[str]
    confidence: str
    description: str
    validator: Optional[Callable[[str], bool]] = None


@dataclass(frozen=True)
class ScanResult:
    findings: List[Finding] = field(default_factory=list)
    redacted_text: str = ""

    @property
    def has_pii(self) -> bool:
        return bool(self.findings)

    def as_dict(self) -> dict:
        return {
            "has_pii": self.has_pii,
            "count": len(self.findings),
            "findings": [f.as_dict() for f in self.findings],
            "redacted_text": self.redacted_text,
        }


def _digits(value: str) -> str:
    return re.sub(r"\D", "", value)


def luhn_valid(value: str) -> bool:
    """Return True when the digits of ``value`` satisfy the Luhn checksum."""
    digits = [int(d) for d in _digits(value)]
    if len(digits) < 13:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def ssn_valid(value: str) -> bool:
    """Reject SSN-shaped numbers that the SSA never issues."""
    digits = _digits(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


DETECTORS: List[Detector] = [
    Detector(
        name="EMAIL",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        confidence="high",
        description="Email address",
    ),
    Detector(
        name="SSN",
        pattern=re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        confidence="high",
        description="US Social Security number",
        validator=ssn_valid,
    ),
    Detector(
        name="CREDIT_CARD",
        pattern=re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        confidence="high",
        description="Credit card number",
        validator=luhn_valid,
    ),
    Detector(
        name="IBAN",
        pattern=re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        confidence="medium",
        description="International bank account number",
    ),
    Detector(
        name="PHONE",
        pattern=re.compile(
            r"(?:\+1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]\d{3}[ .-]\d{4}\b"
        ),
        confidence="medium",
        description="US phone number",
    ),
    Detector(
        name="IPV4",
        pattern=re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                           r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
        confidence="medium",
        description="IPv4 address",
    ),
    Detector(
        name="IPV6",
        pattern=re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b"),
        confidence="medium",
        description="IPv6 address",
    ),
    Detector(
        name="US_PASSPORT",
        pattern=re.compile(r"\b[A-Z]\d{8}\b"),
        confidence="low",
        description="US passport number",
    ),
    Detector(
        name="DATE_OF_BIRTH",
        pattern=re.compile(
            r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b"
        ),
        confidence="low",
        description="Date that may be a date of birth",
    ),
]


def _resolve_overlaps(findings: List[Finding]) -> List[Finding]:
    """Keep the earliest match, preferring the longest one at equal start."""
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start)))
    kept: List[Finding] = []
    last_end = -1
    for finding in ordered:
        if finding.start >= last_end:
            kept.append(finding)
            last_end = finding.end
    return kept


def redact(text: str, findings: List[Finding]) -> str:
    """Replace every finding in ``text`` with a ``[TYPE]`` placeholder."""
    result = text
    for finding in sorted(findings, key=lambda f: f.start, reverse=True):
        result = f"{result[:finding.start]}[{finding.type}]{result[finding.end:]}"
    return result


def scan_text(text: str) -> ScanResult:
    """Scan ``text`` for PII and return the findings plus a redacted copy."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if len(text) > MAX_TEXT_LENGTH:
        raise ValueError(f"text exceeds {MAX_TEXT_LENGTH} characters")

    candidates: List[Finding] = []
    for detector in DETECTORS:
        for match in detector.pattern.finditer(text):
            value = match.group(0)
            if detector.validator and not detector.validator(value):
                continue
            candidates.append(
                Finding(
                    type=detector.name,
                    value=value,
                    start=match.start(),
                    end=match.end(),
                    confidence=detector.confidence,
                )
            )

    findings = _resolve_overlaps(candidates)
    return ScanResult(findings=findings, redacted_text=redact(text, findings))
