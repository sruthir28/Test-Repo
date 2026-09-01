import pytest

from app.detectors import MAX_TEXT_LENGTH, luhn_valid, scan_text, ssn_valid


def types_in(text):
    return {f.type for f in scan_text(text).findings}


@pytest.mark.parametrize(
    "text, expected",
    [
        ("mail me at jane.doe@example.com please", "EMAIL"),
        ("ssn 123-45-6789 on file", "SSN"),
        ("card 4111 1111 1111 1111 charged", "CREDIT_CARD"),
        ("iban GB82WEST12345698765432 confirmed", "IBAN"),
        ("call 415-555-0199 today", "PHONE"),
        ("origin 192.168.1.42 logged", "IPV4"),
        ("host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 down", "IPV6"),
        ("passport X12345678 expires soon", "US_PASSPORT"),
        ("born 04/17/1985 in Ohio", "DATE_OF_BIRTH"),
    ],
)
def test_detects_each_pii_type(text, expected):
    assert expected in types_in(text)


def test_clean_text_has_no_findings():
    result = scan_text("The quarterly report is ready for review at noon.")
    assert result.has_pii is False
    assert result.findings == []
    assert result.redacted_text == "The quarterly report is ready for review at noon."


def test_credit_card_failing_luhn_is_ignored():
    assert "CREDIT_CARD" not in types_in("card 4111 1111 1111 1112 declined")


def test_invalid_ssn_area_is_ignored():
    assert "SSN" not in types_in("ref 666-45-6789 internal")


def test_redaction_masks_every_finding():
    result = scan_text("Email jane@example.com or call 415-555-0199.")
    assert result.redacted_text == "Email [EMAIL] or call [PHONE]."


def test_overlapping_matches_are_resolved_once():
    result = scan_text("SSN 123-45-6789 recorded")
    assert len(result.findings) == 1
    assert result.findings[0].type == "SSN"


def test_findings_report_offsets():
    text = "contact jane@example.com"
    finding = scan_text(text).findings[0]
    assert text[finding.start : finding.end] == "jane@example.com"


def test_multiple_findings_are_ordered_by_position():
    result = scan_text("a@b.com then 415-555-0199 then c@d.com")
    starts = [f.start for f in result.findings]
    assert starts == sorted(starts)
    assert len(result.findings) == 3


def test_oversized_input_is_rejected():
    with pytest.raises(ValueError):
        scan_text("x" * (MAX_TEXT_LENGTH + 1))


def test_non_string_input_is_rejected():
    with pytest.raises(TypeError):
        scan_text(None)


@pytest.mark.parametrize("value, valid", [("4111111111111111", True), ("1234567812345678", False)])
def test_luhn_valid(value, valid):
    assert luhn_valid(value) is valid


@pytest.mark.parametrize("value, valid", [("123-45-6789", True), ("000-45-6789", False), ("123-00-6789", False)])
def test_ssn_valid(value, valid):
    assert ssn_valid(value) is valid
